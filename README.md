# A.D.D.A.P. — Autonomous Driver Downloader And Packager

A PowerShell-based solution that automates the downloading, extraction, and WIM compression of OEM driver packs from **Dell**, **HP**, and **Lenovo**. A companion script dynamically downloads and applies the correct WIM driver pack during OS Deployment (OSD) based on the detected hardware and deployed operating system.

---

## Overview

Managing drivers across a fleet of hardware models is one of the most time-consuming parts of Windows OS deployment. ADDAP solves this by:

1. **Downloading** vendor driver pack catalogs and driver packages from Dell, HP, and Lenovo.
2. **Extracting** the downloaded driver packs.
3. **Compressing** the extracted drivers into WIM format for efficient storage and transfer.
4. **Dynamically applying** the correct WIM driver pack during OSD by matching the target device's hardware identifiers and the operating system being deployed.

All processing is driven by an **XML configuration file** that defines which manufacturers, models, and operating systems to include.

---

## How It Works

### Phase 1 — Driver Pack Creation (Infrastructure / Build Server)

`Invoke-DriverPackageCreator.ps1` is run on a build server or administrative workstation. It:

- Reads the XML settings file (`Content\Settings\Settings.xml`) to determine which manufacturers, models, and OS versions to process.
- Downloads the vendor driver pack catalogs (`.cab` / `.xml`) from Dell, HP, and Lenovo.
- Matches catalog entries to the models and operating systems defined in the XML.
- Downloads the applicable driver packs.
- Extracts driver packs using the bundled **7-Zip** tool (`Tools\X64\7z.exe` / `Tools\X86\7z.exe`).
- Compresses the extracted drivers into **WIM** images.
- Generates a metadata XML file (`DriverPackageList.xml`) that maps each WIM driver pack to its hardware product IDs and target OS.

### Phase 2 — Driver Pack Application (During OSD)

`Invoke-DriverPackageDownload.ps1` runs during an MDT or MECM task sequence. It:

- Detects the current device's manufacturer, product ID, and other hardware identifiers via WMI (`MS_SystemInformation`).
- Reads the deployed OS version and release from the offline Windows image registry hive.
- Reads the metadata XML to find the driver pack that matches both the hardware and the deployed OS.
- Supports **down-leveling** — falling back to an older OS release driver pack when an exact match is not available (can be disabled with `-DisableDownLeveling`).
- Downloads the matching WIM driver pack to the target volume.
- Applies (expands) the WIM to inject drivers into the deployed OS.

### Configuration Generator (Optional)

`Invoke-ConfigurationGenerator.ps1` automates the creation of the XML settings file. It can:

- Query a **SQL database** (e.g., the MECM database) to retrieve a list of all hardware models in the environment.
- Generate the full XML settings file with the correct manufacturer entries and model lists pre-populated.

---

## Repository Structure

```
ADDAP/
├── Invoke-DriverPackageCreator.ps1      # Downloads, extracts, and WIM-compresses driver packs
├── Invoke-DriverPackageDownload.ps1     # Runs during OSD to download and apply driver packs
├── Invoke-ConfigurationGenerator.ps1    # Generates the XML settings file (optional)
├── Content/
│   ├── Settings/
│   │   └── Template.xml                 # XML settings template (manufacturers, models, OS list)
│   ├── DBQueries/
│   │   └── GetProductIDList.sql         # SQL query to retrieve model list from MECM database
│   └── ScheduledTasks/
│       └── Template.xml                 # Scheduled task template for automation
├── Functions/                           # Helper PowerShell functions (dot-sourced at runtime)
│   ├── Convert-FileSize.ps1
│   ├── Copy-ItemWithProgress.ps1
│   ├── Get-WindowsReleaseHistory.ps1
│   ├── Invoke-FileDownload.ps1
│   ├── Invoke-FileDownloadWithProgress.ps1
│   ├── Invoke-RegistryHiveAction.ps1
│   ├── Invoke-SQLDBQuery.ps1
│   ├── Invoke-ScheduledTaskAction.ps1
│   ├── Start-ProcessWithOutput.ps1
│   └── Libraries/                       # .NET assemblies (AlphaFS, HtmlAgilityPack, etc.)
├── Templates/
│   └── TaskSequences/
│       └── MDT/
│           └── ts.xml                   # Sample MDT task sequence template
├── Tools/
│   ├── X64/                             # 64-bit 7-Zip binaries
│   └── X86/                             # 32-bit 7-Zip binaries
└── SampleLogs/                          # Example log output and DISM logs
```

---

## XML Settings Configuration

The settings XML (`Content\Settings\Template.xml`) controls all processing. Key sections:

### Parameters

| Parameter | Description |
|---|---|
| `ApplicationDataRootDirectory` | Root working directory for the script |
| `StagingDirectory` | Temporary staging area for downloads and extraction |
| `DownloadDirectory` | Where raw driver pack downloads are stored |
| `DriverPackageDirectory` | Output directory for the final WIM driver packages |
| `DisableDownload` | Skip downloading (use previously downloaded packs) |
| `Force` | Force reprocessing even if packages already exist |
| `ContinueOnError` | Continue processing remaining models on failure |

### Operating System List

Defines which Windows versions to target (e.g., Windows 10 x64, Windows 11 x64). Supports regex-based matching and a `LatestReleaseOnly` option.

### Manufacturer List

Each manufacturer entry includes:

- **Name** and **Eligibility Expression** — regex to match the device's `SystemManufacturer` WMI property.
- **Catalog URLs** — vendor-specific driver pack catalog download URLs.
- **Product ID Property** — which WMI property to use for hardware matching (`SystemSKU` for Dell, `BaseboardProduct` for HP, `SystemProductName` for Lenovo).
- **Model List** — the specific hardware models to process, each identified by `ProductID`, `BaseboardProduct`, `SystemSKU`, etc.

### Adding a New Model

Run the following PowerShell snippet on the target hardware to generate the XML node, then paste it into the appropriate manufacturer's `<ModelList>` section:

```powershell
$PropertyList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
    $PropertyList.Add(@{Name = 'Enabled'; Expression = {$True}})
    $PropertyList.Add('SystemProductName')
    $PropertyList.Add(@{Name = 'ProductID'; Expression = {$_.BaseboardProduct}})
    $PropertyList.Add('BaseboardProduct')
    $PropertyList.Add('SystemSKU')
    $PropertyList.Add('SystemVersion')
    $PropertyList.Add('SystemFamily')
    $PropertyList.Add('SystemManufacturer')

$MSSystemInformation = Get-CIMInstance -Namespace "root\WMI" -Class "MS_SystemInformation" | Select-Object -Property ($PropertyList)

$XMLAttributes = $MSSystemInformation.PSObject.Properties | ForEach-Object {"$($_.Name)=`"$($_.Value)`""}

$XMLNode = "<Model $($XMLAttributes -Join ' ') />"

Write-Output -InputObject ($XMLNode)

$Null = $XMLNode | Set-Clipboard -Verbose
```

---

## Supported Vendors

| Vendor | Catalog Source | Product ID Property |
|---|---|---|
| **Dell** | [DriverPackCatalog.cab](https://dl.dell.com/catalog/DriverPackCatalog.cab) | `SystemSKU` |
| **HP** | [HPClientDriverPackCatalog.cab](https://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab) | `BaseboardProduct` |
| **Lenovo** | [catalogv2.xml](https://download.lenovo.com/cdrt/td/catalogv2.xml) | `SystemProductName` |

---

## Usage

### Prerequisites

- **PowerShell 3.0** or later.
- **Administrative privileges** (the scripts will self-elevate if not already running as admin).
- Network access to vendor catalog and download URLs.
- For OSD usage: an active **MDT** or **MECM** task sequence environment.
- For SQL-based configuration generation: access to a MECM SQL database.

### Creating Driver Packages

```powershell
# Run from an elevated PowerShell prompt
.\Invoke-DriverPackageCreator.ps1
```

The script will:
1. Create `Content\Settings\Settings.xml` from the template if it does not already exist.
2. Download vendor catalogs.
3. Download, extract, and WIM-compress driver packs for all enabled models and OS versions.

To add the current machine's model to the XML automatically:

```powershell
.\Invoke-DriverPackageCreator.ps1 -AdditionalXMLNodes '<Model Enabled="True" SystemProductName="Latitude 5430" ProductID="0B04" ... />'
```

### Generating Configuration from MECM Database

```powershell
.\Invoke-ConfigurationGenerator.ps1 -QuerySQLDatabase -SQLDatabaseFQDN "sqlserver.domain.com" -SQLDatabaseBName "CM_ABC"
```

### Downloading and Applying Drivers During OSD

Add `Invoke-DriverPackageDownload.ps1` as a **Run PowerShell Script** step in your MDT or MECM task sequence:

```powershell
.\Invoke-DriverPackageDownload.ps1 -DriverPackageRootDirectory "\\server\share\Out-Of-Box-Driver-Packages" -DriverPackageMetadataPath "\\server\share\Out-Of-Box-Driver-Packages\Metadata\DriverPackageList.xml"
```

Key parameters:

| Parameter | Description |
|---|---|
| `-DriverPackageRootDirectory` | UNC path to the root of the driver package share |
| `-DriverPackageMetadataPath` | Path to the metadata XML generated by the creator script |
| `-DisableDownLeveling` | Require an exact OS release match (no fallback) |
| `-Stage` | Stage (copy) the driver content locally before applying |
| `-RandomDelay` | Add a random delay before downloading (load balancing) |
| `-ContinueOnError` | Do not fail the task sequence on error |

---

## Logging

All scripts produce detailed transcript logs:

- **Creator script**: `%WINDIR%\Logs\Software\Invoke-DriverPackageCreator\`
- **Download script (full OS)**: `%WINDIR%\Logs\Software\Invoke-DriverPackageDownload\`
- **Download script (task sequence)**: The task sequence log directory (e.g., `_SMSTSLogPath`)

Log history is automatically maintained with a maximum of **3** log files per script.

---

## Requirements

- Windows PowerShell 3.0+
- Windows 10 / Windows 11 / Windows Server 2016+
- 7-Zip (bundled in `Tools\`)
- .NET Framework (for bundled libraries: AlphaFS, HtmlAgilityPack, NLog, NFluent, Registry)
