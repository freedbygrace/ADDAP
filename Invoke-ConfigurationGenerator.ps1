#Requires -Version 3

<#
    .SYNOPSIS
    Dynamically generates the XML required for the Invoke-DriverPackageCreation powershell script.
          
    .DESCRIPTION
    This script greatly reduces the amount of time it would take to build the XML by hand after determining how many models are deployed within the current environment.
          
    .PARAMETER QuerySQLDatabase
    Determines whether or not to enable the SQL database querying functionality.

    .PARAMETER SQLDatabaseFQDN
    The fully qualified domain name of the SQL database that will be queried. Windows authentication will be used by default, but SQL authentication can be used if modifications are made to the 'Invoke-SQLDBQuery' parameters.

    .PARAMETER SQLDatabaseBName
    The name of the SQL database that will be queried.

    .PARAMETER LogDir
    A valid folder path. If the folder does not exist, it will be created. This parameter can also be specified by the alias "LogPath".

    .PARAMETER ContinueOnError
    Ignore failures.
          
    .EXAMPLE
    Use this command to execute a VBSCript that will launch this powershell script automatically with the specified parameters. This is useful to avoid powershell execution complexities.
    
    cscript.exe /nologo "%FolderPathContainingScript%\%ScriptName%.vbs" /Boolean /ScriptParameter:"%ScriptParameterValue%" /ScriptParameterArray:"%ScriptParameterValue1%,%ScriptParameterValue2%"

    wscript.exe /nologo "%FolderPathContainingScript%\%ScriptName%.vbs" /Boolean /ScriptParameter:"%ScriptParameterValue%" /ScriptParameterArray:"%ScriptParameterValue1%,%ScriptParameterValue2%"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "%FolderPathContainingScript%\%ScriptName%.ps1" -Boolean -ScriptParameter "%ScriptParameterValue%"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -NoLogo -WindowStyle Hidden -Command "& '%FolderPathContainingScript%\%ScriptName%.ps1' -ScriptParameter1 '%ScriptParameter1Value%' -ScriptParameter2 %ScriptParameter2Value% -Boolean"
  
    .NOTES
    If using the database query functionality to get the model list, just ensure that the following columns are returned in order for the XML schema to be generated correctly.

    BaseboardProduct
    SystemFamily
    SystemManufacturer
    SystemProductName
    SystemSKU
    SystemVersion
          
    .LINK
    Place any useful link here where your function or cmdlet can be referenced
#>

[CmdletBinding(SupportsShouldProcess=$True)]
  Param
    (        	     
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Switch]$QuerySQLDatabase,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]$SQLDatabaseFQDN,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]$SQLDatabaseBName,
            
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('LogDir', 'LogPath')]
        [System.IO.DirectoryInfo]$LogDirectory,
            
        [Parameter(Mandatory=$False)]
        [Switch]$ContinueOnError
    )
        
Function Get-AdministrativePrivilege
    {
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
        Write-Output -InputObject ($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    }

If ((Get-AdministrativePrivilege) -eq $False)
    {
        [System.IO.FileInfo]$ScriptPath = "$($MyInvocation.MyCommand.Path)"

        $ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
          $ArgumentList.Add('-ExecutionPolicy Bypass')
          $ArgumentList.Add('-NoProfile')
          $ArgumentList.Add('-NoExit')
          $ArgumentList.Add('-NoLogo')
          $ArgumentList.Add("-File `"$($ScriptPath.FullName)`"")

        $Null = Start-Process -FilePath "$([System.Environment]::SystemDirectory)\WindowsPowershell\v1.0\powershell.exe" -WorkingDirectory "$([System.Environment]::SystemDirectory)" -ArgumentList ($ArgumentList.ToArray()) -WindowStyle Normal -Verb RunAs -PassThru
    }
Else
    {
        #Determine the date and time we executed the function
          $ScriptStartTime = (Get-Date)
  
        #Define Default Action Preferences
            $Script:DebugPreference = 'SilentlyContinue'
            $Script:ErrorActionPreference = 'Stop'
            $Script:VerbosePreference = 'SilentlyContinue'
            $Script:WarningPreference = 'Continue'
            $Script:ConfirmPreference = 'None'
            $Script:WhatIfPreference = $False
    
        #Load WMI Classes
          $Baseboard = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Baseboard" -Property *
          $Bios = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Bios" -Property *
          $ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystem" -Property *
          $OperatingSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_OperatingSystem" -Property *
          $MSSystemInformation = Get-WmiObject -Namespace "root\WMI" -Class "MS_SystemInformation" -Property *

        #Retrieve property values
          $OSArchitecture = $($OperatingSystem.OSArchitecture).Replace("-bit", "").Replace("32", "86").Insert(0,"x").ToUpper()

        #Define variable(s)
          $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss.FFF tt'  ###Monday, January 01, 2019 @ 10:15:34.000 AM###
          [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
          $DateTimeMessageFormat = 'MM/dd/yyyy HH:mm:ss.FFF'  ###03/23/2022 11:12:48.347###
          [ScriptBlock]$GetCurrentDateTimeMessageFormat = {(Get-Date).ToString($DateTimeMessageFormat)}
          $DateFileFormat = 'yyyyMMdd'  ###20190403###
          [ScriptBlock]$GetCurrentDateFileFormat = {(Get-Date).ToString($DateFileFormat)}
          $DateTimeFileFormat = 'yyyyMMdd_HHmmss'  ###20190403_115354###
          [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
          [System.IO.FileInfo]$ScriptPath = "$($MyInvocation.MyCommand.Definition)"
          [System.IO.DirectoryInfo]$ScriptDirectory = "$($ScriptPath.Directory.FullName)"
          [System.IO.DirectoryInfo]$ContentDirectory = "$($ScriptDirectory.FullName)\Content"
          [System.IO.DirectoryInfo]$FunctionsDirectory = "$($ScriptDirectory.FullName)\Functions"
          [System.IO.DirectoryInfo]$ModulesDirectory = "$($ScriptDirectory.FullName)\Modules"
          [System.IO.DirectoryInfo]$ToolsDirectory = "$($ScriptDirectory.FullName)\Tools"
          [System.IO.DirectoryInfo]$ToolsDirectory_OSAll = "$($ToolsDirectory.FullName)\All"
          [System.IO.DirectoryInfo]$ToolsDirectory_OSArchSpecific = "$($ToolsDirectory.FullName)\$($OSArchitecture)"
          [System.IO.DirectoryInfo]$System32Directory = [System.Environment]::SystemDirectory
          [System.IO.DirectoryInfo]$ProgramFilesDirectory = "$($Env:SystemDrive)\Program Files"
          [System.IO.DirectoryInfo]$ProgramFilesx86Directory = "$($Env:SystemDrive)\Program Files (x86)"
          [System.IO.FileInfo]$PowershellPath = "$($System32Directory.FullName)\WindowsPowershell\v1.0\powershell.exe"
          [System.IO.DirectoryInfo]$System32Directory = "$([System.Environment]::SystemDirectory)"
          $IsWindowsPE = Test-Path -Path 'HKLM:\SYSTEM\ControlSet001\Control\MiniNT' -ErrorAction SilentlyContinue
          [System.Text.RegularExpressions.RegexOptions[]]$RegexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [System.Text.RegularExpressions.RegexOptions]::Multiline
          [ScriptBlock]$GetRandomGUID = {[System.GUID]::NewGUID().GUID.ToString().ToUpper()}
          [String]$ParameterSetName = "$($PSCmdlet.ParameterSetName)"
          $TextInfo = (Get-Culture).TextInfo
          $Script:LASTEXITCODE = 0
          $TerminationCodes = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
            $TerminationCodes.Add('Success', @(0))
            $TerminationCodes.Add('Warning', @(5000..5999))
            $TerminationCodes.Add('Error', @(6000..6999))
          $Script:WarningCodeIndex = 0
          [ScriptBlock]$GetAvailableWarningCode = {$TerminationCodes.Warning[$Script:WarningCodeIndex]; $Script:WarningCodeIndex++}
          $Script:ErrorCodeIndex = 0
          [ScriptBlock]$GetAvailableErrorCode = {$TerminationCodes.Error[$Script:ErrorCodeIndex]; $Script:ErrorCodeIndex++}
          $LoggingDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'    
            $LoggingDetails.Add('LogMessage', $Null)
            $LoggingDetails.Add('WarningMessage', $Null)
            $LoggingDetails.Add('ErrorMessage', $Null)
          $RegularExpressionTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
            $RegularExpressionTable.Base64 = '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$' -As [Regex]
          $CommonParameterList = New-Object -TypeName 'System.Collections.Generic.List[String]'
            $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::CommonParameters)
            $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
          $HashAlgorithm = 'SHA256'

          #Define the error handling definition
            [ScriptBlock]$ErrorHandlingDefinition = {
                                                        If (($Null -ieq $Script:LASTEXITCODE) -or ($Script:LASTEXITCODE -eq 0))
                                                          {
                                                              [Int]$Script:LASTEXITCODE = $GetAvailableErrorCode.InvokeReturnAsIs()
                                                          }
                                                        
                                                        $ErrorMessageList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $ErrorMessageList.Add('Message', $_.Exception.Message)
                                                          $ErrorMessageList.Add('Category', $_.Exception.ErrorRecord.FullyQualifiedErrorID)
                                                          $ErrorMessageList.Add('ExitCode', $Script:LASTEXITCODE)
                                                          $ErrorMessageList.Add('Script', $_.InvocationInfo.ScriptName)
                                                          $ErrorMessageList.Add('LineNumber', $_.InvocationInfo.ScriptLineNumber)
                                                          $ErrorMessageList.Add('LinePosition', $_.InvocationInfo.OffsetInLine)
                                                          $ErrorMessageList.Add('Code', $_.InvocationInfo.Line.Trim())

                                                        ForEach ($ErrorMessage In $ErrorMessageList.GetEnumerator())
                                                          {
                                                              $LoggingDetails.ErrorMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  ERROR: $($ErrorMessage.Key): $($ErrorMessage.Value)"
                                                              Write-Warning -Message ($LoggingDetails.ErrorMessage) -Verbose
                                                          }

                                                        Switch (($ContinueOnError.IsPresent -eq $False) -or ($ContinueOnError -eq $False))
                                                          {
                                                              {($_ -eq $True)}
                                                                {                  
                                                                    Throw
                                                                }
                                                          }
                                                    }
	  
        #Determine default parameter value(s)                                              
          Switch ($True)
            {
                {([String]::IsNullOrEmpty($LogDirectory) -eq $True) -or ([String]::IsNullOrWhiteSpace($LogDirectory) -eq $True)}
                  {
                      [System.IO.DirectoryInfo]$ApplicationDataRootDirectory = "$($Env:ProgramData)\Invoke-DriverPackageCreator"

                      [System.IO.DirectoryInfo]$LogDirectory = "$($ApplicationDataRootDirectory.FullName)\Logs"
                  }       
            }

        #Start transcripting (Logging)
          [System.IO.FileInfo]$ScriptLogPath = "$($LogDirectory.FullName)\$($ScriptPath.BaseName)_$($GetCurrentDateFileFormat.Invoke()).log"
          If ($ScriptLogPath.Directory.Exists -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($ScriptLogPath.Directory.FullName)}
          Start-Transcript -Path "$($ScriptLogPath.FullName)" -Force -WhatIf:$False
	
        #Log any useful information                                     
          [String]$CmdletName = $MyInvocation.MyCommand.Name
                                                   
          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of script `"$($CmdletName)`" began on $($ScriptStartTime.ToString($DateTimeLogFormat))"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script Path = $($ScriptPath.FullName)"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

          [String[]]$AvailableScriptParameters = (Get-Command -Name ($ScriptPath.FullName)).Parameters.GetEnumerator() | Where-Object {($_.Value.Name -inotin $CommonParameterList)} | ForEach-Object {"-$($_.Value.Name):$($_.Value.ParameterType.Name)"}
          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Available Script Parameter(s) = $($AvailableScriptParameters -Join ', ')"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

          [String[]]$SuppliedScriptParameters = $PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key):$($_.Value.GetType().Name)"}
          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supplied Script Parameter(s) = $($SuppliedScriptParameters -Join ', ')"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
          
          Switch ($True)
            {
                {([String]::IsNullOrEmpty($ParameterSetName) -eq $False)}
                  {
                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Parameter Set Name = $($ParameterSetName)"
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                  }
            }
          
          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Command Line: $((Get-WMIObject -Namespace 'Root\CIMv2' -Class 'Win32_Process' -Filter "ProcessID = $($PID)").CommandLine)"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($PSBoundParameters.Count) command line parameter(s) were specified."
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

          $OperatingSystemDetailsTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
            $OperatingSystemDetailsTable.ProductName = $OperatingSystem.Caption -ireplace '(Microsoft\s+)', ''
            $OperatingSystemDetailsTable.Version = $OperatingSystem.Version
            $OperatingSystemDetailsTable.Architecture = $OperatingSystem.OSArchitecture

          $OperatingSystemRegistryDetails = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
            $OperatingSystemRegistryDetails.Add((New-Object -TypeName 'PSObject' -Property @{Alias = ''; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; ValueName = 'UBR'; Value = $Null}))
            $OperatingSystemRegistryDetails.Add((New-Object -TypeName 'PSObject' -Property @{Alias = 'ReleaseVersion'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; ValueName = 'ReleaseID'; Value = $Null}))
            $OperatingSystemRegistryDetails.Add((New-Object -TypeName 'PSObject' -Property @{Alias = 'ReleaseID'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; ValueName = 'DisplayVersion'; Value = $Null}))

          ForEach ($OperatingSystemRegistryDetail In $OperatingSystemRegistryDetails)
            {
                $OperatingSystemRegistryDetail.Value = Try {(Get-Item -Path $OperatingSystemRegistryDetail.Path).GetValue($OperatingSystemRegistryDetail.ValueName)} Catch {}

                :NextOSDetail Switch (([String]::IsNullOrEmpty($OperatingSystemRegistryDetail.Value) -eq $False) -and ([String]::IsNullOrWhiteSpace($OperatingSystemRegistryDetail.Value) -eq $False))
                  {
                      {($_ -eq $True)}
                        {
                            Switch ($OperatingSystemRegistryDetail.ValueName)
                              {
                                  {($_ -ieq 'UBR')}
                                    {
                                        $OperatingSystemDetailsTable.Version = $OperatingSystemDetailsTable.Version + '.' + $OperatingSystemRegistryDetail.Value

                                        Break NextOSDetail
                                    }
                              }

                            Switch (([String]::IsNullOrEmpty($OperatingSystemRegistryDetail.Alias) -eq $False) -and ([String]::IsNullOrWhiteSpace($OperatingSystemRegistryDetail.Alias) -eq $False))
                              {
                                  {($_ -eq $True)}
                                    {
                                        $OperatingSystemDetailsTable.$($OperatingSystemRegistryDetail.Alias) = $OperatingSystemRegistryDetail.Value
                                    }

                                  Default
                                    {
                                        $OperatingSystemDetailsTable.$($OperatingSystemRegistryDetail.ValueName) = $OperatingSystemRegistryDetail.Value
                                    }
                              }
                        }

                      Default
                        {
                            $OperatingSystemDetailsTable.$($OperatingSystemRegistryDetail.ValueName) = $OperatingSystemRegistryDetail.Value
                        }
                  }   
            }
    
          ForEach ($OperatingSystemDetail In $OperatingSystemDetailsTable.GetEnumerator())
            {
                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($OperatingSystemDetail.Key): $($OperatingSystemDetail.Value)"
                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
            }
      
          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Powershell Version: $($PSVersionTable.PSVersion.ToString())"
          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
      
          $ExecutionPolicyList = Get-ExecutionPolicy -List
  
          For ($ExecutionPolicyListIndex = 0; $ExecutionPolicyListIndex -lt $ExecutionPolicyList.Count; $ExecutionPolicyListIndex++)
            {
                $ExecutionPolicy = $ExecutionPolicyList[$ExecutionPolicyListIndex]

                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The powershell execution policy is currently set to `"$($ExecutionPolicy.ExecutionPolicy.ToString())`" for the `"$($ExecutionPolicy.Scope.ToString())`" scope."
                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
            }
    
        #Log hardware information
          $MSSystemInformationMembers = $MSSystemInformation.PSObject.Properties | Where-Object {($_.MemberType -imatch '^NoteProperty$|^Property$') -and ($_.Name -imatch '^Base.*|Bios.*|System.*$') -and ($_.Name -inotmatch '^.*Major.*|.*Minor.*|.*Properties.*$')} | Sort-Object -Property @('Name')
          
          Switch ($MSSystemInformationMembers.Count -gt 0)
            {
                {($_ -eq $True)}
                  {
                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to display device information properties from the `"$($MSSystemInformation.__CLASS)`" WMI class located within the `"$($MSSystemInformation.__NAMESPACE)`" WMI namespace. Please Wait..."
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
  
                      ForEach ($MSSystemInformationMember In $MSSystemInformationMembers)
                        {
                            [String]$MSSystemInformationMemberName = ($MSSystemInformationMember.Name)
                            [String]$MSSystemInformationMemberValue = $MSSystemInformation.$($MSSystemInformationMemberName)
        
                            Switch ([String]::IsNullOrEmpty($MSSystemInformationMemberValue))
                              {
                                  {($_ -eq $False)}
                                    {
                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($MSSystemInformationMemberName) = $($MSSystemInformationMemberValue)"
                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                    }
                              }
                        }
                  }

                Default
                  {
                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The `"MSSystemInformation`" WMI class could not be found."
                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                  }
            }

        #region Log Cleanup
          [Int]$MaximumLogHistory = 3
          
          $LogList = Get-ChildItem -Path ($LogDirectory.FullName) -Filter "$($ScriptPath.BaseName)_*" -Recurse -Force | Where-Object {($_ -is [System.IO.FileInfo])}

          $SortedLogList = $LogList | Sort-Object -Property @('LastWriteTime') -Descending | Select-Object -Skip ($MaximumLogHistory)

          Switch ($SortedLogList.Count -gt 0)
            {
                {($_ -eq $True)}
                  {
                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - There are $($SortedLogList.Count) log file(s) requiring cleanup."
                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                      
                      For ($SortedLogListIndex = 0; $SortedLogListIndex -lt $SortedLogList.Count; $SortedLogListIndex++)
                        {
                            Try
                              {
                                  $Log = $SortedLogList[$SortedLogListIndex]

                                  $LogAge = New-TimeSpan -Start ($Log.LastWriteTime) -End (Get-Date)

                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to cleanup log file `"$($Log.FullName)`". Please Wait... [Last Modified: $($Log.LastWriteTime.ToString($DateTimeMessageFormat))] [Age: $($LogAge.Days.ToString()) day(s); $($LogAge.Hours.ToString()) hours(s); $($LogAge.Minutes.ToString()) minute(s); $($LogAge.Seconds.ToString()) second(s)]."
                                  Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                  
                                  $Null = [System.IO.File]::Delete($Log.FullName)
                              }
                            Catch
                              {
                  
                              }   
                        }
                  }

                Default
                  {
                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - There are $($SortedLogList.Count) log file(s) requiring cleanup."
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                  }
            }
        #endregion

        #region Import Dependency Modules
          If (($ModulesDirectory.Exists -eq $True) -and ($ModulesDirectory.GetDirectories().Count -gt 0))
            {
                $Modules = Get-Module -Name "$($ModulesDirectory.FullName)\*" -ListAvailable -ErrorAction Stop 

                $ModuleGroups = $Modules | Group-Object -Property @('Name')

                ForEach ($ModuleGroup In $ModuleGroups)
                  {
                      $LatestModuleVersion = $ModuleGroup.Group | Sort-Object -Property @('Version') -Descending | Select-Object -First 1
      
                      If ($Null -ine $LatestModuleVersion)
                        {
                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to import dependency powershell module `"$($LatestModuleVersion.Name)`" [Version: $($LatestModuleVersion.Version.ToString())]. Please Wait..."
                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                            Try {$Null = Import-Module -Name "$($LatestModuleVersion.Path)" -Global -DisableNameChecking -Force -Verbose:$False} Catch {}
                        }
                  }
            }
        #endregion
        
        #region Dot Source Dependency Scripts
          #Dot source any additional script(s) from the functions directory. This will provide flexibility to add additional functions without adding complexity to the main script and to maintain function consistency.
            Try
              {
                  If ($FunctionsDirectory.Exists -eq $True)
                    {
                        $AdditionalFunctionsFilter = New-Object -TypeName 'System.Collections.Generic.List[String]'
                          $AdditionalFunctionsFilter.Add('*.ps1')
        
                        $AdditionalFunctionsToImport = Get-ChildItem -Path "$($FunctionsDirectory.FullName)" -Include ($AdditionalFunctionsFilter) -Recurse -Force | Where-Object {($_ -is [System.IO.FileInfo])}
        
                        $AdditionalFunctionsToImportCount = $AdditionalFunctionsToImport | Measure-Object | Select-Object -ExpandProperty Count
        
                        If ($AdditionalFunctionsToImportCount -gt 0)
                          {                    
                              ForEach ($AdditionalFunctionToImport In $AdditionalFunctionsToImport)
                                {
                                    Try
                                      {
                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to dot source the functions contained within the dependency script `"$($AdditionalFunctionToImport.Name)`". Please Wait... [Script Path: `"$($AdditionalFunctionToImport.FullName)`"]"
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                          
                                          . "$($AdditionalFunctionToImport.FullName)"
                                      }
                                    Catch
                                      {
                                          $ErrorHandlingDefinition.Invoke()
                                      }
                                }
                          }
                    }
              }
            Catch
              {
                  $ErrorHandlingDefinition.Invoke()          
              }
        #endregion

        #region Load any required libraries
          [System.IO.DirectoryInfo]$LibariesDirectory = "$($FunctionsDirectory.FullName)\Libraries"

          Switch ([System.IO.Directory]::Exists($LibariesDirectory.FullName))
            {
                {($_ -eq $True)}
                  {
                      $LibraryPatternList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                        #$LibraryPatternList.Add('')

                      Switch ($LibraryPatternList.Count -gt 0)
                        {
                            {($_ -eq $True)}
                              {
                                  $LibraryList = Get-ChildItem -Path ($LibariesDirectory.FullName) -Include ($LibraryPatternList.ToArray()) -Recurse -Force | Where-Object {($_ -is [System.IO.FileInfo])}

                                  $LibraryListCount = ($LibraryList | Measure-Object).Count
            
                                  Switch ($LibraryListCount -gt 0)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              For ($LibraryListIndex = 0; $LibraryListIndex -lt $LibraryListCount; $LibraryListIndex++)
                                                {
                                                    $Library = $LibraryList[$LibraryListIndex]
            
                                                    [Byte[]]$LibraryBytes = [System.IO.File]::ReadAllBytes($Library.FullName)
            
                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to load assembly `"$($Library.FullName)`". Please Wait..."
                                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
            
                                                    $Null = [System.Reflection.Assembly]::Load($LibraryBytes)     
                                                }
                                          }
                                    }
                              }
                        }          
                  }
            }
        #endregion

        #Perform script action(s)
          Try
            {                                              
                #region Define the driver package creation settings XML schema
                  $GetXMLDateCreated = {(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm')}

                  $ManufacturerList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                  $ManufacturerListEntry = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $ManufacturerListEntry.Enabled = $True
                      $ManufacturerListEntry.Name = 'Dell'
                      $ManufacturerListEntry.EligibilityExpression = '(^.*Dell.*$)'
                      $ManufacturerListEntry.ProductIDExpression = @{Name = 'BaseboardProduct'; Expression = {If ($_.SystemSKU.Length -lt 6) {$_.SystemSKU} Else {$Null}}}
                      $ManufacturerListEntry.ProductIDPropertyName = 'SystemSKU'
                      $ManufacturerListEntry.URLs = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                          $ManufacturerListEntry.URLs.DriverPackCatalog = 'https://dl.dell.com/catalog/DriverPackCatalog.cab'
                          $ManufacturerListEntry.URLs.DownloadBase = 'https://dl.dell.com'
                      $ManufacturerListEntry.ModelList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                      If ($QuerySQLDatabase.IsPresent -eq $False)
                        {
                            $ManufacturerListEntry.ModelList.Add((New-Object -TypeName 'PSObject' -Property @{Enabled = $False; SystemProductName = 'Latitude 5430'; ProductID = '0B04'; BaseboardProduct = '01Y2TP'; SystemSKU = '0B04'; SystemVersion = ''; SystemFamily = 'Latitude'; SystemManufacturer = $ManufacturerListEntry.Name}))
                        }

                  $ManufacturerListObject = New-Object -TypeName 'PSObject' -Property ($ManufacturerListEntry)
                    $ManufacturerList.Add($ManufacturerListEntry)

                  $ManufacturerListEntry = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $ManufacturerListEntry.Enabled = $True
                      $ManufacturerListEntry.Name = 'HP'
                      $ManufacturerListEntry.EligibilityExpression = '(^.*HP.*$)|(^.*Hewlett.*Packard.*$)'
                      $ManufacturerListEntry.ProductIDExpression = @{Name = 'BaseboardProduct'; Expression = {[Regex]::Match($_.BaseboardProduct, '^\w{4}').Value.ToUpper()}}
                      $ManufacturerListEntry.ProductIDPropertyName = 'BaseboardProduct'
                      $ManufacturerListEntry.URLs = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                          $ManufacturerListEntry.URLs.DriverPackCatalog = 'https://ftp.hp.com/pub/caps-softpaq/cmit/HPClientDriverPackCatalog.cab'
                          $ManufacturerListEntry.URLs.DownloadBase = ''
                      $ManufacturerListEntry.ModelList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                      If ($QuerySQLDatabase.IsPresent -eq $False)
                        {
                            $ManufacturerListEntry.ModelList.Add((New-Object -TypeName 'PSObject' -Property @{Enabled = $False; SystemProductName = 'HP ZBook Studio G7 Mobile Workstation'; ProductID = '8736'; BaseboardProduct = '8736'; SystemSKU = '8YP41AV'; SystemVersion = ''; SystemFamily = '103C_5336AN HP ZBook'; SystemManufacturer = $ManufacturerListEntry.Name}))
                        }   

                  $ManufacturerListObject = New-Object -TypeName 'PSObject' -Property ($ManufacturerListEntry)
                    $ManufacturerList.Add($ManufacturerListEntry)

                  $ManufacturerListEntry = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $ManufacturerListEntry.Enabled = $True
                      $ManufacturerListEntry.Name = 'Lenovo'
                      $ManufacturerListEntry.EligibilityExpression = '(^.*LENOVO.*$)'
                      $ManufacturerListEntry.ProductIDExpression = @{Name = 'BaseboardProduct'; Expression = {[Regex]::Match($_.SystemProductName, '^\w{4}').Value.ToUpper()}}
                      $ManufacturerListEntry.ProductIDPropertyName = 'SystemProductName'
                      $ManufacturerListEntry.URLs = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                          $ManufacturerListEntry.URLs.DriverPackCatalog = 'https://download.lenovo.com/cdrt/td/catalogv2.xml'
                          $ManufacturerListEntry.URLs.DownloadBase = ''
                      $ManufacturerListEntry.ModelList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                      If ($QuerySQLDatabase.IsPresent -eq $False)
                        {
                            $ManufacturerListEntry.ModelList.Add((New-Object -TypeName 'PSObject' -Property @{Enabled = $False; SystemProductName = '10AXS2CQ00'; ProductID = '10AX'; BaseboardProduct = '10AXS2CQ00'; SystemSKU = 'LENOVO_MT_10AX'; SystemVersion = 'ThinkCentre M73'; SystemFamily = 'To be filled by O.E.M.'; SystemManufacturer = $ManufacturerListEntry.Name}))
                        }

                  $ManufacturerListObject = New-Object -TypeName 'PSObject' -Property ($ManufacturerListEntry)
                    $ManufacturerList.Add($ManufacturerListObject)

              Switch ($QuerySQLDatabase.IsPresent)
                  {
                      {($_ -eq $True)}
                          {
                              Switch (Test-Connection -ComputerName $SQLDatabaseFQDN -Count 1 -Quiet)
                                  {
                                      {($_ -eq $True)}
                                          {
                                              $ModelListConfigurationDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                  $ModelListConfigurationDetails.ModelListQueryPath = "$($ContentDirectory.FullName)\DBQueries\GetProductIDList.sql" -As [System.IO.FileInfo]
                                                  
                                              Switch ([System.IO.File]::Exists($ModelListConfigurationDetails.ModelListQueryPath.FullName))
                                                  {
                                                      {($_ -eq $True)}
                                                          {
                                                              $ModelListConfigurationDetails.ModelListQueryContents = [System.IO.File]::ReadAllText($ModelListConfigurationDetails.ModelListQueryPath.FullName)
                              
                                                              $InvokeSQLDBQueryParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                  $InvokeSQLDBQueryParameters.Server = $SQLDatabaseFQDN
                                                                  $InvokeSQLDBQueryParameters.Database = $SQLDatabaseBName
                                                              $InvokeSQLDBQueryParameters.DBQueryList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                                  $InvokeSQLDBQueryParameters.DBQueryList.Add($ModelListConfigurationDetails.ModelListQueryContents)
                                                              $InvokeSQLDBQueryParameters.ContinueOnError = $False
                                                              $InvokeSQLDBQueryParameters.Verbose = $True
                                                              
                                                              $SQLDBQueryResultSet = (Invoke-SQLDBQuery @InvokeSQLDBQueryParameters).ResultSet001 | Sort-Object -Property {$_.SystemProductName.Length} -Descending

                                                              $SQLDBQueryResultSetCount = ($SQLDBQueryResultSet | Measure-Object).Count

                                                              Switch ($SQLDBQueryResultSetCount -gt 0)
                                                                  {
                                                                      {($_ -eq $True)}
                                                                          {                                                                        
                                                                              ForEach ($SQLDBQueryResult In  $SQLDBQueryResultSet)
                                                                                  {                    
                                                                                      $SQLDBQueryResultDetails = $ManufacturerList | Where-Object {($SQLDBQueryResult.SystemManufacturer -imatch $_.EligibilityExpression.ToString())}

                                                                                      Switch ($Null -ine $SQLDBQueryResultDetails)
                                                                                          {
                                                                                              {($_ -eq $True)}
                                                                                                  {                                                                                                        
                                                                                                      $ProductID = Try {($SQLDBQueryResult | Select-Object -Property ($SQLDBQueryResultDetails.ProductIDExpression)).BaseBoardProduct} Catch {$Null} 
                                                                                                      
                                                                                                      Switch (([String]::IsNullOrEmpty($ProductID) -eq $False) -and ([String]::IsNullOrWhiteSpace($ProductID) -eq $False))
                                                                                                          {
                                                                                                              {($_ -eq $True)}
                                                                                                                  {                                                                                                                        
                                                                                                                      $SQLDBQueryResult.SystemManufacturer = $SQLDBQueryResultDetails.Name

                                                                                                                      $SQLDBQueryResult | Add-Member -Name 'Enabled' -Value $True -MemberType NoteProperty  
                                                                                                                      $SQLDBQueryResult | Add-Member -Name 'ProductID' -Value ($ProductID) -MemberType NoteProperty
                                                                                                  
                                                                                                                      Switch ($SQLDBQueryResultDetails.ModelList.ProductID -inotcontains $SQLDBQueryResult.ProductID)
                                                                                                                          {
                                                                                                                              {($_ -eq $True)}
                                                                                                                                  {
                                                                                                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add product ID `"$($SQLDBQueryResult.ProductID)`" [Model: $($SQLDBQueryResult.SystemProductName)] manufactured by `"$($SQLDBQueryResultDetails.Name)`" to the model list. Please Wait..."
                                                                                                                                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                                                                    
                                                                                                                                      $SQLDBQueryResultDetails.ModelList.Add($SQLDBQueryResult)
                                                                                                                                  }
                                                                                                                          }
                                                                                                                  }
                                                                                                          }    
                                                                                                  }

                                                                                              Default
                                                                                                  {
                                                                                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Manufacturer `"$($SQLDBQueryResult.SystemManufacturer)`" is currently unsupported."
                                                                                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                                  }
                                                                                          }         
                                                                                  }
                                                                          }
                                                                  }
                                                          }

                                                      Default
                                                          {
                                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The SQL query file does not exist. [Path: $($ModelListConfigurationDetails.ModelListQueryPath.FullName)]"
                                                              Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                          }
                                                  }
                                          }

                                      Default
                                          {
                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Unable to contact the specified SQL database server. [Server: $($SQLDatabaseFQDN)]"
                                              Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                          }
                                  }
                          }
                  }

                  $XMLWriterSettings = New-Object -TypeName 'System.XML.XMLWriterSettings'
                      $XMLWriterSettings.Indent = $True
                      $XMLWriterSettings.IndentChars = "`t" * 1
                      $XMLWriterSettings.Encoding = [System.Text.Encoding]::UTF8
                      $XMLWriterSettings.NewLineHandling = [System.XML.NewLineHandling]::None
                      $XMLWriterSettings.ConformanceLevel = [System.XML.ConformanceLevel]::Auto

                  $XMLStringBuilder = New-Object -TypeName 'System.Text.StringBuilder'

                  $XMLWriter = [System.XML.XMLTextWriter]::Create($XMLStringBuilder, $XMLWritersettings)

                  [ScriptBlock]$AddXMLWriterNewLine = {$XMLWriter.WriteWhitespace(("`r`n" * 2))}

                  $XMLWriter.WriteStartDocument()

                  $AddXMLWriterNewLine.Invoke()

                  $XMLWriter.WriteProcessingInstruction("xml-stylesheet", "type='text/xsl' href='style.xsl'")

                  $AddXMLWriterNewLine.Invoke()

                  $XMLWriter.WriteComment(@'
Please specify the configuration settings that will be used by the driver package creation powershell script.
'@)

                  $AddXMLWriterNewLine.Invoke()

                  $XMLWriter.WriteComment(@'


By default, the settings XML will be automatically modified by the 'Invoke-DriverPackageCreation' script to include the model you execute the script on, but only if it matches one of the manufacturers within the XML.

To add a model manually, copy and paste the following code into the  Powershell ISE on the specific model you want to add to this XML.

The text will be automatically copied to the clipboard.

Add the model under the desired manufacturer in order to the entry to be processed correctly.
    
### Begin Code Snippet ###
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
### End Code Snippet ###

<ModelList>
    ### Copy and paste the generated text from the clipboard in between the 'ModelList' section for the desired manufacturer ###
</ModelList>

As an example, the following details are available from the following powershell command

Get-CIMInstance -Namespace 'Root\WMI' -Class 'MS_SystemInformation'

BaseBoardManufacturer  : Dell Inc.
BaseBoardProduct       : 01Y2TP
BaseBoardVersion       : A00
BiosMajorRelease       : 1
BiosMinorRelease       : 6
BIOSReleaseDate        : 09/05/2022
BIOSVendor             : Dell Inc.
BIOSVersion            : 1.6.1
ECFirmwareMajorRelease : 255
ECFirmwareMinorRelease : 255
InstanceName           : ROOT\mssmbios\0000_0
SystemFamily           : Latitude
SystemManufacturer     : Dell Inc.
SystemProductName      : Latitude 5430
SystemSKU              : 0B04
SystemVersion          : 


'@)

                $AddXMLWriterNewLine.Invoke()

                $XMLWriter.WriteStartElement('Settings')

                $TargetScriptParameterList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'ApplicationDataRootDirectory'; Value = '$($Env:Windir)\Temp\$($ScriptPath.BaseName)'; Type = 'System.IO.DirectoryInfo'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'StagingDirectory'; Value = '$($ApplicationDataRootDirectory.FullName)'; Type = 'System.IO.DirectoryInfo'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'DownloadDirectory'; Value = '$($StagingDirectory.FullName)\Downloads'; Type = 'System.IO.DirectoryInfo'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'DriverPackageDirectory'; Value = '$($ApplicationDataRootDirectory.FullName)\Out-Of-Box-Driver-Packages'; Type = 'System.IO.DirectoryInfo'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'DisableDownload'; Value = $False; Type = 'Boolean'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'EnableRobocopyIPG'; Value = $False; Type = 'Boolean'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'Force'; Value = $False; Type = 'Boolean'})))
                  $TargetScriptParameterList.Add((New-Object -TypeName 'PSObject' -Property ([Ordered]@{Name = 'ContinueOnError'; Value = $False; Type = 'Boolean'})))

                  Switch ($TargetScriptParameterList.Count -gt 0)
                  {
                      {($_ -eq $True)}
                        {
                            $XMLWriter.WriteStartElement('ParameterList')

                            For ($TargetScriptParameterListIndex = 0; $TargetScriptParameterListIndex -lt $TargetScriptParameterList.Count; $TargetScriptParameterListIndex++)
                              {
                                  $TargetScriptParameterListItem = $TargetScriptParameterList[$TargetScriptParameterListIndex]

                                  $XMLWriter.WriteStartElement('Parameter')

                                  ForEach ($Property In $TargetScriptParameterListItem.PSObject.Properties)
                                    {
                                        $XMLWriter.WriteAttributeString($Property.Name, $Property.Value)
                                    }

                                  $XMLWriter.WriteEndElement()
                              }

                            $XMLWriter.WriteEndElement()
                        }
                  }
                        
                $XMLWriter.WriteStartElement('OperatingSystemList')

                $OperatingSystemList = Get-WindowsReleaseHistory | Sort-Object -Property @('Name') -Unique

                ForEach ($OperatingSystem In $OperatingSystemList)
                    {
                        $XMLWriter.WriteStartElement('OperatingSystem')

                        $XMLWriter.WriteAttributeString('Enabled', $True)
                        $XMLWriter.WriteAttributeString('Vendor', $OperatingSystem.Vendor)
                        $XMLWriter.WriteAttributeString('Name', $OperatingSystem.Name)
                        $XMLWriter.WriteAttributeString('NameExpression', ".*$([Regex]::Match($OperatingSystem.Name, '\d+').Value).*")
                        $XMLWriter.WriteAttributeString('ArchitectureExpression', '.*64.*')
                        $XMLWriter.WriteAttributeString('ReleaseExpression', '.*')
                        $XMLWriter.WriteAttributeString('LatestReleaseOnly', $True)

                        $XMLWriter.WriteEndElement()
                    }
                
                $XMLWriter.WriteEndElement()

                $XMLWriter.WriteStartElement('ManufacturerList')

                $ManufacturerListGroups = $ManufacturerList | Group-Object -Property {$_.Name}

                ForEach ($ManufacturerListGroup In $ManufacturerListGroups)
                    {
                        $ManufacturerListGroupDetails = $ManufacturerListGroup.Group

                        $XMLWriter.WriteStartElement('Manufacturer')

                        $XMLWriter.WriteAttributeString('Enabled', $ManufacturerListGroupDetails.Enabled)
                        $XMLWriter.WriteAttributeString('Name', $ManufacturerListGroupDetails.Name)
                        $XMLWriter.WriteAttributeString('EligibilityExpression', $ManufacturerListGroupDetails.EligibilityExpression)
                        $XMLWriter.WriteAttributeString('ProductIDPropertyName', $ManufacturerListGroupDetails.ProductIDPropertyName)
                        
                        $XMLWriter.WriteStartElement('URLs')

                        $XMLWriter.WriteAttributeString('DriverPackCatalog', $ManufacturerListGroupDetails.URLs.DriverPackCatalog)
                        $XMLWriter.WriteAttributeString('DownloadBase', $ManufacturerListGroupDetails.URLs.DownloadBase)

                        $XMLWriter.WriteEndElement()

                        $XMLWriter.WriteStartElement('ModelList')

                        ForEach ($Model In $ManufacturerListGroupDetails.ModelList)
                            {
                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add a XML node for product ID `"$($Model.ProductID)`" [Model: $($Model.SystemProductName)] manufactured by `"$($ManufacturerListGroupDetails.Name)`". Please Wait..."
                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                              
                                $XMLWriter.WriteStartElement('Model')

                                $XMLWriter.WriteAttributeString('Enabled', $Model.Enabled)
                                $XMLWriter.WriteAttributeString('SystemProductName', $Model.SystemProductName)
                                $XMLWriter.WriteAttributeString('ProductID', $Model.ProductID)
                                $XMLWriter.WriteAttributeString('BaseboardProduct', $Model.BaseboardProduct)
                                $XMLWriter.WriteAttributeString('SystemSKU', $Model.SystemSKU)
                                $XMLWriter.WriteAttributeString('SystemVersion', $Model.SystemVersion)
                                $XMLWriter.WriteAttributeString('SystemFamily', $Model.SystemFamily)
                                $XMLWriter.WriteAttributeString('SystemManufacturer', $Model.SystemManufacturer)
                                
                                $XMLWriter.WriteEndElement()
                            }

                        $XMLWriter.WriteEndElement()

                        $XMLWriter.WriteEndElement()
                    }

                $XMLWriter.WriteEndElement()
                
                $XMLWriter.WriteEndElement()

                $XMLWriter.WriteEndDocument()

                $XMLWriter.Flush()

                $XMLWriter.Close()

                $DriverPackageCreationXMLContents = $XMLStringBuilder.ToString()

                [System.IO.FileInfo]$DriverPackageCreationXMLExportPath = "$($ContentDirectory.FullName)\Settings\Template.xml"

                [Scriptblock]$ExportDriverPackageCreationXML = {
                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to export the driver package settings XML to `"$($DriverPackageCreationXMLExportPath.FullName)`". Please Wait..."
                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                    If ([System.IO.Directory]::Exists($DriverPackageCreationXMLExportPath.Directory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DriverPackageCreationXMLExportPath.Directory.FullName)}

                                                                    $Null = [System.IO.File]::WriteAllText($DriverPackageCreationXMLExportPath.FullName, $DriverPackageCreationXMLContents, $XMLWriterSettings.Encoding)
                                                               }

                Switch ([System.IO.File]::Exists($DriverPackageCreationXMLExportPath.FullName))
                  {
                      {($_ -eq $True)}
                        {      
                            $MemoryStream = New-Object -TypeName 'System.IO.MemoryStream'

                            $StreamWriter = New-Object -TypeName 'System.IO.StreamWriter' -ArgumentList ($MemoryStream)
                              $Null = $StreamWriter.Write($DriverPackageCreationXMLContents)
                              $Null = $StreamWriter.Flush()
                              $Null = $MemoryStream.Position = 0

                            $DriverPackageCreationXMLContentHash = Get-FileHash -InputStream $MemoryStream -Algorithm ($HashAlgorithm)

                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - New Driver Package Settings XML Hash: $($DriverPackageCreationXMLContentHash.Hash.ToUpper())"
                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                            $DriverPackageCreationXMLExportPathHash = Get-FileHash -Path ($DriverPackageCreationXMLExportPath.FullName) -Algorithm ($HashAlgorithm)

                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Current Driver Package Settings XML Hash: $($DriverPackageCreationXMLExportPathHash.Hash.ToUpper())"
                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                            Switch ($DriverPackageCreationXMLContentHash.Hash.ToUpper() -ne $DriverPackageCreationXMLExportPathHash.Hash.ToUpper())
                              {
                                  {($_ -eq $True)}
                                    {
                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The XML metadata file `"$($DriverPackageCreationXMLExportPath.FullName)`" requires an update."
                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                        $Null = $ExportDriverPackageCreationXML.InvokeReturnAsIs()
                                    }

                                  Default
                                    {
                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The XML metadata file `"$($DriverPackageCreationXMLExportPath.FullName)`" does not require an update."
                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                    }
                              }
                        }

                      Default
                      {
                          $Null = $ExportDriverPackageCreationXML.InvokeReturnAsIs()
                      }
                  }
                #endregion
                                                                          
                $Script:LASTEXITCODE = $TerminationCodes.Success[0]
            }
          Catch
            {
                $ErrorHandlingDefinition.Invoke()
            }
          Finally
            {
                Try
                  {
                      #Determine the date and time the function completed execution
                        $ScriptEndTime = (Get-Date)

                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script execution of `"$($CmdletName)`" ended on $($ScriptEndTime.ToString($DateTimeLogFormat))"
                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                      #Log the total script execution time  
                        $ScriptExecutionTimespan = New-TimeSpan -Start ($ScriptStartTime) -End ($ScriptEndTime)

                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script execution took $($ScriptExecutionTimespan.Hours.ToString()) hour(s), $($ScriptExecutionTimespan.Minutes.ToString()) minute(s), $($ScriptExecutionTimespan.Seconds.ToString()) second(s), and $($ScriptExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
            
                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Exiting script `"$($ScriptPath.FullName)`" with exit code $($Script:LASTEXITCODE)."
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
            
                      Stop-Transcript
                  }
                Catch
                  {
            
                  }
            }
    }