#Requires -Version 3

<#
    .SYNOPSIS
    A brief overview of what your function does

    .DESCRIPTION
    Slightly more detailed description of what your function does

    .PARAMETER LogDir
    A valid folder path. If the folder does not exist, it will be created. This parameter can also be specified by the alias "LogPath".

    .PARAMETER ContinueOnError
    Ignore failures.

    .EXAMPLE
    Use this command to execute a VBSCript that will launch this powershell script automatically with the specified parameters. This is useful to avoid powershell execution complexities.

    cscript.exe /nologo "%FolderPathContainingScript%\%ScriptName%.vbs" /SwitchParameter /ScriptParameter:"%ScriptParameterValue%" /ScriptParameterArray:"%ScriptParameterValue1%,%ScriptParameterValue2%"

    wscript.exe /nologo "%FolderPathContainingScript%\%ScriptName%.vbs" /SwitchParameter /ScriptParameter:"%ScriptParameterValue%" /ScriptParameterArray:"%ScriptParameterValue1%,%ScriptParameterValue2%"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "%FolderPathContainingScript%\%ScriptName%.ps1" -SwitchParameter -ScriptParameter "%ScriptParameterValue%"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -NoLogo -WindowStyle Hidden -Command "& '%FolderPathContainingScript%\%ScriptName%.ps1' -ScriptParameter1 '%ScriptParameter1Value%' -ScriptParameter2 %ScriptParameter2Value% -SwitchParameter"

    .NOTES
    Any useful tidbits

    .LINK
    Place any useful link here where your function or cmdlet can be referenced
#>

[CmdletBinding(SupportsShouldProcess=$True)]
  Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('AXN')]
        [String[]]$AdditionalXMLNodes
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
          $DateTimeXMLFormat = 'yyyy-MM-ddTHH:mm:ss'  ###2022-10-24T12:45:15###
          [ScriptBlock]$GetCurrentDateTimeXMLFormat = {(Get-Date).ToString($DateTimeXMLFormat)}
          $DateDriverPackReleaseFormat = 'yyyy-MM-dd'  ###2019-04-03###
          [ScriptBlock]$GetCurrentDateDriverPackReleaseFormat = {(Get-Date).ToString($DateDriverPackReleaseFormat)}
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
          [System.IO.FileInfo]$7ZipPath = "$($ToolsDirectory_OSArchSpecific.FullName)\7z.exe"
					[String]$HashAlgorithm = 'SHA256'

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

                                                        Switch (($ContinueOnError -eq $False) -or ($ContinueOnError -eq $False))
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
                      [System.IO.DirectoryInfo]$LogDirectory = "$($Env:Windir)\Logs\Software\$($ScriptPath.BaseName)"
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

                      $MSSystemInformationTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

                      ForEach ($MSSystemInformationMember In $MSSystemInformationMembers)
                        {
                            [String]$MSSystemInformationMemberName = ($MSSystemInformationMember.Name)
                            [String]$MSSystemInformationMemberValue = $MSSystemInformation.$($MSSystemInformationMemberName)

                            $MSSystemInformationTable.$($MSSystemInformationMemberName) = $MSSystemInformationMemberValue

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
                        $LibraryPatternList.Add('AlphaFS.dll')

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
                $ProcessExecutionTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                  $ProcessExecutionTable.CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent() -As [Security.Principal.WindowsIdentity]
                  $ProcessExecutionTable.CurrentProcessSID = $ProcessExecutionTable.CurrentProcessToken.User -As [Security.Principal.SecurityIdentifier]
                  $ProcessExecutionTable.ProcessNTAccount = $ProcessExecutionTable.CurrentProcessToken.Name -As [String]
                  $ProcessExecutionTable.ProcessNTAccountSID = $ProcessExecutionTable.CurrentProcessSID.Value -As [String]
                  $ProcessExecutionTable.IsAdmin = ($ProcessExecutionTable.CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544') -As [Boolean]
                  $ProcessExecutionTable.IsLocalSystemAccount = $ProcessExecutionTable.CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalSystemSid') -As [Boolean]
                  $ProcessExecutionTable.IsLocalServiceAccount = $ProcessExecutionTable.CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalServiceSid') -As [Boolean]
                  $ProcessExecutionTable.IsNetworkServiceAccount = $ProcessExecutionTable.CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'NetworkServiceSid') -As [Boolean]
                  $ProcessExecutionTable.IsServiceAccount = ($ProcessExecutionTable.CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-6') -As [Boolean]
                  $ProcessExecutionTable.IsProcessUserInteractive = [System.Environment]::UserInteractive -As [Boolean]
                  $ProcessExecutionTable.LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $Null)).Translate([Security.Principal.NTAccount]).Value -As [String]
                  $ProcessExecutionTable.LocalUsersGroup = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([Security.Principal.WellKnownSidType]::'BuiltinUsersSid', $Null)).Translate([System.Security.Principal.NTAccount]).Value -As [String]
                  $ProcessExecutionTable.LocalAdministratorsGroup = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([Security.Principal.WellKnownSidType]::'BuiltinAdministratorsSid', $Null)).Translate([System.Security.Principal.NTAccount]).Value -As [String]
                  $ProcessExecutionTable.IsSessionZero = If (($ProcessExecutionTable.IsLocalSystemAccount -eq $True) -or ($ProcessExecutionTable.IsLocalServiceAccount -eq $True) -or ($ProcessExecutionTable.IsNetworkServiceAccount -eq $True) -or ($ProcessExecutionTable.IsServiceAccount -eq $True)) {$True} Else {$False}
                  $ProcessExecutionTable.Is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem -As [Boolean]
                  $ProcessExecutionTable.Is64BitProcess = [System.Environment]::Is64BitProcess -As [Boolean]
                  $ProcessExecutionTable.CommandLine = [System.Environment]::CommandLine -As [String]

                  [System.IO.FileInfo]$SettingsTemplate = "$($ContentDirectory.FullName)\Settings\Template.xml"

                  [System.IO.FileInfo]$SettingsPath = "$($SettingsTemplate.Directory.FullName)\Settings.xml"

                  Switch ([System.IO.File]::Exists($SettingsPath.FullName))
                    {
                        {($_ -eq $True)}
                          {
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The settings XML configuration file `"$($SettingsPath.FullName)`" already exists."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                          }
  
                        {($_ -eq $False)}
                          {
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The settings XML configuration file `"$($SettingsPath.FullName)`" does not exist and will be created."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                            
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create settings XML configuration file `"$($SettingsPath.FullName)`" from the settings XML template file `"$($SettingsTemplate.FullName)`". Please Wait..."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
  
                              Switch ([System.IO.Directory]::Exists($SettingsPath.Directory.FullName))
                                {
                                    {($_ -eq $False)}
                                      {
                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create non-existent directory `"$($SettingsPath.Directory.FullName)`". Please Wait..."
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                        
                                          $Null = [System.IO.Directory]::CreateDirectory($SettingsPath.Directory.FullName)
                                      }
                                }
  
                              $Null = Copy-Item -Path ($SettingsTemplate.FullName) -Destination ($SettingsPath.FullName) -Force
                          }
                    }
              
                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Settings Path: $($SettingsPath.FullName)"
                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                $Script:SettingsTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                  $Script:SettingsTable.XMLModificationCount = 0
                  $Script:SettingsTable.GetXMLDateAdded = {(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')}

                [ScriptBlock]$ReadXMLContent = {
                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to load the configuration settings from `"$($SettingsPath.FullName)`". Please Wait..."
                                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                    $Script:SettingsXMLContent = [System.IO.File]::ReadAllText($SettingsPath.FullName)

                                                    $Script:SettingsXMLObject = New-Object -TypeName 'System.Xml.XmlDocument'
                                                      $Script:SettingsXMLObject.PreserveWhitespace = $True

                                                    $Null = $Script:SettingsXMLObject.LoadXml($Script:SettingsXMLContent)
 
                                                    $Script:SettingsTable.OperatingSytemList = $Script:SettingsXMLObject.SelectNodes('/Settings/OperatingSystemList//OperatingSystem') | Where-Object {($_.Enabled -eq $True)}
                                                    $Script:SettingsTable.ManufacturerList = $Script:SettingsXMLObject.SelectNodes('/Settings/ManufacturerList//Manufacturer')
                                                    
                                               }

                $Null = $ReadXMLContent.InvokeReturnAsIs()

                #Create variable(s) for script parameters stored within the XML
                  $XMLParameterObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                  $XMLParameterNodeList = $Script:SettingsXMLObject.SelectNodes('/Settings/ParameterList//Parameter')

                  ForEach ($XMLParameterNode In $XMLParameterNodeList)
                    {
                        $XMLParameterObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary' 
                          $XMLParameterObjectProperties.Name = $XMLParameterNode.Name
                          $XMLParameterObjectProperties.Type = $XMLParameterNode.Type
                          $XMLParameterObjectProperties.OriginalValue = $XMLParameterNode.Value
                          $XMLParameterObjectProperties.ExpandedValue = $ExecutionContext.InvokeCommand.ExpandString([System.Environment]::ExpandEnvironmentVariables($XMLParameterObjectProperties.OriginalValue))

                          Switch ($XMLParameterObjectProperties.Type)
                            {
                                {($_ -iin @('Switch'))}
                                  {
                                      $XMLParameterObjectProperties.TypeCastedValue = New-Object -TypeName 'System.Management.Automation.SwitchParameter' -ArgumentList @($XMLParameterObjectProperties.ExpandedValue)
                                  } 

                                  {($_ -iin @('Boolean'))}
                                  {
                                      $XMLParameterObjectProperties.TypeCastedValue = [Boolean]::Parse($XMLParameterObjectProperties.ExpandedValue)
                                  }

                                Default
                                  {
                                      $XMLParameterObjectProperties.TypeCastedValue = $XMLParameterObjectProperties.ExpandedValue -As "$($XMLParameterObjectProperties.Type)"
                                  }
                            }
                           
                          $SetVariableParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                            $SetVariableParameters.Name = $XMLParameterObjectProperties.Name
                            $SetVariableParameters.Value = $XMLParameterObjectProperties.TypeCastedValue
                            $SetVariableParameters.Force = $True
                            $SetVariableParameters.Scope = 'Script'
                            $SetVariableParameters.Verbose = $False

                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create the $($SetVariableParameters.Scope.ToLower()) scope powershell variable `"`$$($SetVariableParameters.Name)`" of type `"[$($XMLParameterObjectProperties.Type)]`" with a value of `"$($SetVariableParameters.Value)`". Please Wait..."
                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                          $Null = Set-Variable @SetVariableParameters
                        
                        $XMLParameterObject = New-Object -TypeName 'PSObject' -Property ($XMLParameterObjectProperties)

                        $XMLParameterObjectList.Add($XMLParameterObject)
                    }
                                                                                 
                [System.IO.DirectoryInfo]$LocalDriverPackageDirectory = "$($StagingDirectory.FullName)\Packages"

                [System.IO.DirectoryInfo]$CatalogDirectory = "$($ApplicationDataRootDirectory.FullName)\Catalogs"

                $WindowsReleaseHistory = Get-WindowsReleaseHistory -Verbose

                #Attempt to type cast the additional models that were provided within the additional XML node list parameter   
                  $AdditionalXMLNodeList = New-Object -TypeName 'System.Collections.Generic.List[String]'

                  Switch ($AdditionalXMLNodes.Count -gt 0)
                    {
                        {($_ -eq $True)}
                          {
                              ForEach ($AdditionalXMLNode In $AdditionalXMLNodes)
                                {
                                    $AdditionalXMLNodeList.Add($AdditionalXMLNode)
                                }
                          }
                    }

                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($AdditionalXMLNodeList.Count) additional XML model nodes were specified."
                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                  Switch ($AdditionalXMLNodeList.Count -gt 0)
                    {
                        {($_ -eq $True)}
                          {
                              $ValidAdditionalXMLNodeList = New-Object -TypeName 'System.Collections.Generic.List[System.XML.XMLNode]'

                              For ($AdditionalXMLNodeListIndex = 0; $AdditionalXMLNodeListIndex -lt $AdditionalXMLNodeList.Count; $AdditionalXMLNodeListIndex++)
                                {
                                    $AdditionalXMLNodeListItem = $AdditionalXMLNodeList[$AdditionalXMLNodeListIndex]

                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to validate additional XML node `"$($AdditionalXMLNodeListItem)`". Please Wait..."
                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                    $XMLNodeConverter = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                      $XMLNodeConverter.XMLTextReaderArguments = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                        $XMLNodeConverter.XMLTextReaderArguments.Add((New-Object -TypeName 'System.IO.StringReader' -ArgumentList $AdditionalXMLNodeListItem))
                                      $XMLNodeConverter.XMLTextReader = New-Object -TypeName 'System.XML.XMLTextReader' -ArgumentList ($XMLNodeConverter.XMLTextReaderArguments.ToArray())
                                    $XMLNodeConverter.XMLDocument = New-Object -TypeName 'System.XML.XMLDocument'
                                      $XMLNodeConverter.XMLNodeError = $Null
                                      $XMLNodeConverter.XMLNode = Try {$XMLNodeConverter.XMLDocument.ReadNode($XMLNodeConverter.XMLTextReader) -As [System.XML.XMLNode]} Catch {$Null; $XMLNodeConverter.XMLNodeError = $_.Exception.Message}
                                      $XMLNodeConverter.XMLNodeIsValid = $XMLNodeConverter.XMLNode -is [System.XML.XMLNode]

                                    Switch ($XMLNodeConverter.XMLNodeIsValid)
                                      {
                                          {($_ -eq $True)}
                                            {
                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The provided XML node is valid."
                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                    
                                                $ValidAdditionalXMLNodeList.Add($XMLNodeConverter.XMLNode)
                                            }

                                          Default
                                            {
                                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The provided XML node is invalid. [Error: $($XMLNodeConverter.XMLNodeError)]"
                                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose       
                                            }
                                      }
                                }

                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($ValidAdditionalXMLNodeList.Count) of $($AdditionalXMLNodeList.Count) XML nodes were successfully type casted and added to the list of valid XML node objects."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                          }
                    }


                Try
                  {
                      ForEach ($Manufacturer In $SettingsTable.ManufacturerList)
                        {
                            Switch ($Manufacturer.Enabled)
                              {
                                  {($_ -eq $True)}
                                    {
                                        $ManufacturerSettingsTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                          $ManufacturerSettingsTable.ModelList = ($Script:SettingsTable.ManufacturerList | Where-Object {($_.Name -ieq $Manufacturer.Name)}).ModelList.Model

                                        $AdditionalModelNodeList = $ValidAdditionalXMLNodeList | Where-Object {($_.SystemManufacturer -imatch $Manufacturer.EligibilityExpression)}

                                        $AdditionalModelListCount = ($AdditionalModelNodeList | Measure-Object).Count

                                        Switch ($AdditionalModelListCount -gt 0)
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($AdditionalModelListCount) additional model(s) whose system manufacturer matches `"$($Manufacturer.EligibilityExpression)`" need to be added to the model list for `"$($Manufacturer.Name)`"."
                                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                    
                                                    [Int]$XMLModificationCount = 0
                                                    
                                                    ForEach ($AdditionalModelNode In $AdditionalModelNodeList)
                                                      {
                                                          Switch ($ManufacturerSettingsTable.ModelList.ProductID -inotcontains $AdditionalModelNode.ProductID)
                                                            {
                                                                {($_ -eq $True)}
                                                                  {
                                                                      Try
                                                                        {
                                                                            $OneTabNode = $Script:SettingsXMLObject.CreateTextNode("`t")
                                                                            $ThreeTabNode = $Script:SettingsXMLObject.CreateTextNode("`t`t`t")
                                                                            $WhitespaceNode = $Script:SettingsXMLObject.CreateTextNode("`r`n")
                                                                            
                                                                            $ImportedAdditionalModelNode = $Script:SettingsXMLObject.ImportNode($AdditionalModelNode, $True)

                                                                            $ModelListNode = ($Script:SettingsTable.ManufacturerList | Where-Object {($_.Name -ieq $Manufacturer.Name)}).ModelList
 
                                                                            $Null = $ModelListNode.AppendChild($OneTabNode)

                                                                            $Null = $ModelListNode.AppendChild($ImportedAdditionalModelNode)

                                                                            $Null = $ModelListNode.AppendChild($WhitespaceNode)

                                                                            $Null = $ModelListNode.AppendChild($ThreeTabNode)

                                                                            $XMLModificationCount = $XMLModificationCount + 1
                                                                        }
                                                                      Catch
                                                                        {
                                                                            $ErrorMessageList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                              $ErrorMessageList.Add('Message', $_.Exception.Message)
                                                                              $ErrorMessageList.Add('Category', $_.Exception.ErrorRecord.FullyQualifiedErrorID)
                                                                              $ErrorMessageList.Add('LineNumber', $_.InvocationInfo.ScriptLineNumber)
                                                                              $ErrorMessageList.Add('LinePosition', $_.InvocationInfo.OffsetInLine)
                                                                              $ErrorMessageList.Add('Code', $_.InvocationInfo.Line.Trim())

                                                                            ForEach ($ErrorMessage In $ErrorMessageList.GetEnumerator())
                                                                              {
                                                                                  $LoggingDetails.ErrorMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  ERROR: $($ErrorMessage.Key): $($ErrorMessage.Value)"
                                                                                  Write-Warning -Message ($LoggingDetails.ErrorMessage) -Verbose
                                                                              }
                                                                        }
                                                                      Finally
                                                                        {
                                                                              
                                                                        }
                                                                  }

                                                                Default
                                                                  {
                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - XML node already exists! [Content: $($AdditionalModelNode.OuterXml)]"
                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                  }
                                                            }         
                                                      }
                                                }
                                          }
                                    }
                              }
                        }

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($XMLModificationCount) change(s) need to be committed into `"$($SettingsPath.FullName)`"."
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                      Switch ($XMLModificationCount -gt 0)
                        {
                            {($_ -eq $True)}
                              {                                  
                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to save `"$($SettingsPath.FullName)`". Please Wait..."
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                  
                                  $Null = $Script:SettingsXMLObject.Save($SettingsPath.FullName)

                                  $Null = Start-Sleep -Seconds 3

                                  $Null = $ReadXMLContent.InvokeReturnAsIs()
                              }
                        }    
                  }
                Catch
                  {
                      
                  }
                Finally
                  {
                      
                  }

                $DriverPackDownloadList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                ForEach ($Manufacturer In $SettingsTable.ManufacturerList)
                  {
                      Try
                        {
                            Switch ($Manufacturer.Enabled)
                              {
                                  {($_ -eq $True)}
                                    {
                                        $ManufacturerSettingsTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                          $ManufacturerSettingsTable.ModelList = ($Script:SettingsTable.ManufacturerList | Where-Object {($_.Name -ieq $Manufacturer.Name)}).ModelList.Model

                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process the driver pack catalog for `"$($Manufacturer.Name)`". Please Wait..."
                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                        $DownloadDriverPackCatalog = Invoke-FileDownloadWithProgress -URL ($Manufacturer.URLs.DriverPackCatalog) -Destination "$($CatalogDirectory.FullName)\$($Manufacturer.Name)" -Verbose

                                        Switch ($DownloadDriverPackCatalog.DownloadPath.Extension -imatch '\.(cab)')
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    [System.IO.FileInfo]$DriverPackCatalogExtractionPath = "$($DownloadDriverPackCatalog.DownloadPath.Directory.FullName)\$($DownloadDriverPackCatalog.DownloadPath.BaseName).xml"

                                                    Switch (($DownloadDriverPackCatalog.DownloadRequired -eq $True) -or ([System.IO.File]::Exists($DriverPackCatalogExtractionPath.FullName) -eq $False))
                                                      {
                                                          {($_ -eq $True)}
                                                            {
                                                                $Null = Start-ProcessWithOutput -FilePath "$($System32Directory.FullName)\expand.exe" -ArgumentList "`"$($DownloadDriverPackCatalog.DownloadPath.FullName)`" `"$($DriverPackCatalogExtractionPath.FullName)`"" -AcceptableExitCodeList @('0') -CreateNoWindow -Verbose
                                                            }
                                                      }
                                                }
                                          }

                                        $DriverPackCatalogPath = Get-ChildItem -Path ($DownloadDriverPackCatalog.DownloadPath.Directory.FullName) -Filter '*.xml' -Force | Where-Object {($_ -is [System.IO.FileInfo])} | Sort-Object -Property @('LastWriteTime') -Descending | Select-Object -First 1

                                        $DriverPackCatalogContents = [System.IO.File]::ReadAllText($DriverPackCatalogPath.FullName)

                                        $DriverPackCatalog = New-Object -TypeName 'System.Xml.XmlDocument'
                                          $DriverPackCatalog.PreserveWhitespace = $True
                                          $DriverPackCatalog.LoadXml($DriverPackCatalogContents)

                                        ForEach ($Model In $ManufacturerSettingsTable.ModelList)
                                          {
                                              Switch ($Model.Enabled)
                                                {
                                                    {($_ -eq $True)}
                                                      {
                                                          ForEach ($OperatingSystemEntry In $Script:SettingsTable.OperatingSytemList)
                                                            {
                                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to search the `"$($Manufacturer.Name)`" driver pack catalog for `"$($OperatingSystemEntry.Name)`" drivers for model `"$($Model.BaseboardProduct)`" [Manufacturer: $($Model.SystemManufacturer)] [Model: $($model.SystemProductName)] [Alias: $($Model.SystemVersion)] [SKU: $($Model.SystemSKU)]. Please Wait..."
                                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                $OperatingSystemEntryReleaseHistory = $WindowsReleaseHistory | Where-Object {($_.Name -imatch $OperatingSystemEntry.NameExpression)}

                                                                $OperatingSystemEntryVersion = $OperatingSystemEntryReleaseHistory[0].Version

                                                                Switch ($Manufacturer.Name)
                                                                  {
                                                                      {($_ -iin @('Dell'))}
                                                                        {
                                                                            $DriverPackSearchResults = $DriverPackCatalog.DriverPackManifest.DriverPackage | Where-Object {($_.Type -inotmatch '(^.*WinPE.*$)') -and ($_.SupportedSystems.Brand.Model.SystemID -ieq $Model.ProductID) -and ($_.SupportedOperatingSystems.OperatingSystem.OSCode -imatch $OperatingSystemEntry.NameExpression) -and ($_.SupportedOperatingSystems.OperatingSystem.OSArch -imatch $OperatingSystemEntry.ArchitectureExpression)}

                                                                            $DriverPackSearchResultCount = ($DriverPackSearchResults | Measure-Object).Count

                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchResultCount) result(s) were returned from the driver pack search."
                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                       
                                                                            Switch ($OperatingSystemEntry.LatestReleaseOnly)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        $DriverPackSearchFilteredResults = $DriverPackSearchResults | Sort-Object {(Get-Date -Date ($_.DateTime))} -Descending | Select-Object -First 1
                                                                                    }

                                                                                  Default
                                                                                    {
                                                                                        $DriverPackSearchFilteredResults = $DriverPackSearchResults | Sort-Object {(Get-Date -Date ($_.DateTime))} -Descending
                                                                                    }
                                                                              }

                                                                            $DriverPackSearchFilteredResultCount = ($DriverPackSearchFilteredResults | Measure-Object).Count

                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchFilteredResultCount) result(s) remain after filtering, and sorting."
                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                            Switch ($DriverPackSearchFilteredResultCount -gt 0)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        ForEach ($DriverPackSearchResult In $DriverPackSearchFilteredResults)
                                                                                          {
                                                                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add driver pack `"$($DriverPackSearchResult.Name.Display.'#cdata-section')`" [Release: $($DriverPackSearchResult.releaseID)] [Version: $($DriverPackSearchResult.dellVersion)] released on $((Get-Date -Date $DriverPackSearchResult.DateTime).ToString($DateTimeLogFormat)). Please Wait..."
                                                                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                              $DriverPackDownloadProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                $DriverPackDownloadProperties.Enabled = $True
                                                                                                $DriverPackDownloadProperties.Manufacturer = $Manufacturer.Name
                                                                                                $DriverPackDownloadProperties.BaseboardProduct = $Model.BaseboardProduct
                                                                                                $DriverPackDownloadProperties.SystemFamily = $Model.SystemFamily
                                                                                                $DriverPackDownloadProperties.SystemManufacturer = $Model.SystemManufacturer
                                                                                                $DriverPackDownloadProperties.SystemProductName = $Model.SystemProductName
                                                                                                $DriverPackDownloadProperties.SystemSKU = $Model.SystemSKU
                                                                                                $DriverPackDownloadProperties.SystemVersion = $Model.SystemVersion
                                                                                                $DriverPackDownloadProperties.ProductIDList = $DriverPackSearchResult.SupportedSystems.Brand.Model.SystemID
                                                                                                $DriverPackDownloadProperties.ProductID = $DriverPackDownloadProperties.ProductIDList[0]
                                                                                                $DriverPackDownloadProperties.OSName = "$($OperatingSystemEntry.Name)"
                                                                                                $DriverPackDownloadProperties.OSAlias = "W$($OperatingSystemEntry.Name -ireplace '(\D+)', '')"
                                                                                                $DriverPackDownloadProperties.OSVersionMinimum = $OperatingSystemEntryVersion.ToString()
                                                                                                $DriverPackDownloadProperties.OSReleaseIDMinimum = "All"
                                                                                                $DriverPackDownloadProperties.OSArchitecture = $DriverPackSearchResult.SupportedOperatingSystems.OperatingSystem.OSArch.ToUpper()
                                                                                                $DriverPackDownloadProperties.DriverPackReleaseID = "$($DriverPackSearchResult.ReleaseID)"
                                                                                                $DriverPackDownloadProperties.DriverPackReleaseVersion = "$($DriverPackSearchResult.DellVersion)"
                                                                                                $DriverPackDownloadProperties.DriverPackReleaseDate = Try {(Get-Date -Date $DriverPackSearchResult.DateTime).ToString($DateDriverPackReleaseFormat)} Catch {$DriverPackSearchResult.DateTime}
                                                                                                $DriverPackDownloadProperties.DriverPackInfoURL = "$($DriverPackSearchResult.ImportantInfo.URL)"
                                                                                                $DriverPackDownloadProperties.DirectoryPath = "$($DriverPackDownloadProperties.Manufacturer)\$($DriverPackDownloadProperties.SystemSKU)\$($DriverPackDownloadProperties.OSAlias)\$($DriverPackDownloadProperties.OSArchitecture)"
                                                                                                $DriverPackDownloadProperties.FileBaseName = "$($DriverPackDownloadProperties.Manufacturer)-$($DriverPackDownloadProperties.SystemSKU)-$($DriverPackDownloadProperties.DriverPackReleaseID)-$($DriverPackDownloadProperties.DriverPackReleaseVersion)-$($DriverPackDownloadProperties.OSAlias)-$($DriverPackDownloadProperties.OSArchitecture)-$($DriverPackDownloadProperties.OSReleaseIDMinimum)"
                                                                                                
                                                                                                $DriverPackDownloadProperties.FileBaseName = $DriverPackDownloadProperties.FileBaseName.Split([System.IO.Path]::GetInvalidFileNameChars()) -Join ''

                                                                                                $DriverPackDownloadProperties.FileName = "$($DriverPackDownloadProperties.FileBaseName).wim"
                                                                                                $DriverPackDownloadProperties.FilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.FileName)"
                                                                                                $DriverPackDownloadProperties.MetadataFileName = "$($DriverPackDownloadProperties.FileBaseName).json"
                                                                                                $DriverPackDownloadProperties.MetadataFilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.MetadataFileName)"
                                                                                                $DriverPackDownloadProperties.DownloadLinkList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                  $DriverPackDownloadProperties.DownloadLinkList.DriverPack = "$($Manufacturer.URLs.DownloadBase)/$($DriverPackSearchResult.Path)"
                                                                                                  $DriverPackDownloadProperties.DownloadLinkList.DriverPackMetadata = "$($Manufacturer.URLs.DownloadBase)/$($DriverPackSearchResult.DriverPackMetadataInfo.Path)"

                                                                                              $DriverPackDownloadObject = New-Object -TypeName 'PSObject' -Property ($DriverPackDownloadProperties)

                                                                                              $DriverPackDownloadList.Add($DriverPackDownloadObject)
                                                                                          }
                                                                                    }
                                                                              }
                                                                        }

                                                                      {($_ -iin @('HP'))}
                                                                        {
                                                                            $DriverPackSearchResults = New-Object -TypeName 'System.Collections.Generic.List[Object]'

                                                                            $CatalogSearchResults = $DriverPackCatalog.SelectNodes('/*/*/ProductOSDriverPackList/ProductOSDriverPack') | Where-Object {($_.SystemID.Split(',').Trim() -icontains $Model.ProductID) -and ($_.OSName -imatch $OperatingSystemEntry.NameExpression) -and ($_.OSName -imatch $OperatingSystemEntry.ReleaseExpression) -and ($_.Architecture -imatch $OperatingSystemEntry.ArchitectureExpression)} | Sort-Object -Property @('SoftpaqID') -Unique

                                                                            $CatalogList = $DriverPackCatalog.SelectNodes('/*/*/SoftPaqList/SoftPaq')

                                                                            ForEach ($CatalogSearchResult In $CatalogSearchResults)
                                                                              {
                                                                                  $CatalogSearchResultItem = $CatalogList | Where-Object {($_.ID -ieq $CatalogSearchResult.SoftpaqID)}
                                                                                    $CatalogSearchResultItem | Add-Member -Name 'SystemModel' -Value ($CatalogSearchResult.SystemName) -MemberType NoteProperty -Force
                                                                                    $CatalogSearchResultItem | Add-Member -Name 'SystemIDList' -Value ($CatalogSearchResult.SystemID.Split(',').Trim()) -MemberType NoteProperty -Force
                                                                                    $CatalogSearchResultItem | Add-Member -Name 'OperatingSystemName' -Value ($CatalogSearchResult.OSName) -MemberType NoteProperty -Force
                                                                                    $CatalogSearchResultItem | Add-Member -Name 'OperatingSystemArchitecture' -Value ($CatalogSearchResult.Architecture) -MemberType NoteProperty -Force
                                                                                    $CatalogSearchResultItem | Add-Member -Name 'OperatingSystemID' -Value ($CatalogSearchResult.OSID) -MemberType NoteProperty -Force

                                                                                  $DriverPackSearchResults.Add($CatalogSearchResultItem)
                                                                              }

                                                                            $DriverPackSearchResultCount = ($DriverPackSearchResults | Measure-Object).Count

                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchResultCount) result(s) were returned from the driver pack search."
                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                            Switch ($OperatingSystemEntry.LatestReleaseOnly)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        $DriverPackSearchFilteredResults = $DriverPackSearchResults | Sort-Object {(Get-Date -Date ($_.DateReleased))} -Descending | Select-Object -First 1
                                                                                    }

                                                                                  Default
                                                                                    {
                                                                                        $DriverPackSearchFilteredResults = $DriverPackSearchResults | Sort-Object {(Get-Date -Date ($_.DateReleased))} -Descending
                                                                                    }
                                                                              }

                                                                            $DriverPackSearchFilteredResultCount = ($DriverPackSearchFilteredResults | Measure-Object).Count

                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchFilteredResultCount) result(s) remain after filtering, and sorting."
                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                            Switch ($DriverPackSearchFilteredResultCount -gt 0)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        ForEach ($DriverPackSearchResult In $DriverPackSearchFilteredResults)
                                                                                          {
                                                                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add driver pack `"$($DriverPackSearchResult.Name)`" [Version: $($DriverPackSearchResult.Version)] released on $((Get-Date -Date $DriverPackSearchResult.DateReleased).ToString($DateTimeLogFormat)). Please Wait..."
                                                                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                              $DriverPackDownloadProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                $DriverPackDownloadProperties.Enabled = $True
                                                                                                $DriverPackDownloadProperties.Manufacturer = $Manufacturer.Name
                                                                                                $DriverPackDownloadProperties.BaseboardProduct = $Model.BaseboardProduct
                                                                                                $DriverPackDownloadProperties.SystemFamily = $Model.SystemFamily
                                                                                                $DriverPackDownloadProperties.SystemManufacturer = $Model.SystemManufacturer
                                                                                                $DriverPackDownloadProperties.SystemProductName = $Model.SystemProductName
                                                                                                $DriverPackDownloadProperties.SystemSKU = $Model.SystemSKU
                                                                                                $DriverPackDownloadProperties.SystemVersion = $Model.SystemVersion
                                                                                                $DriverPackDownloadProperties.ProductIDList = $DriverPackSearchResult.SystemIDList | ForEach-Object {$_.ToUpper()}
                                                                                                $DriverPackDownloadProperties.ProductID = $DriverPackDownloadProperties.ProductIDList[0]
                                                                                                $DriverPackDownloadProperties.OSName = "$($OperatingSystemEntry.Name)"
                                                                                                $DriverPackDownloadProperties.OSAlias = "W$($OperatingSystemEntry.Name -ireplace '(\D+)', '')"
                                                                                                  
                                                                                                $DriverPackOSDetails = $OperatingSystemEntryReleaseHistory | Where-Object {($_.ReleaseID -ieq [Regex]::Match($DriverPackSearchResult.OperatingSystemName, $_.ReleaseID).Value)} | Select-Object -First 1

                                                                                                Switch ($Null -ine $DriverPackOSDetails)
                                                                                                  {
                                                                                                      {($_ -eq $True)}
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.OSVersionMinimum = $DriverPackOSDetails.Version.ToString()

                                                                                                            $DriverPackDownloadProperties.OSReleaseIDMinimum = $DriverPackOSDetails.ReleaseID
                                                                                                        }

                                                                                                      Default
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.OSVersionMinimum = $OperatingSystemEntryVersion.ToString()

                                                                                                            $DriverPackDownloadProperties.OSReleaseIDMinimum = "All"
                                                                                                        }
                                                                                                  }
  
                                                                                                $DriverPackDownloadProperties.OSArchitecture = 'NA'

                                                                                                Switch ($DriverPackSearchResult.OperatingSystemArchitecture)
                                                                                                  {
                                                                                                      {($_ -imatch '(^.*32.*$)')}
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.OSArchitecture = 'X86'
                                                                                                        }

                                                                                                      {($_ -imatch '(^.*64.*$)')}
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.OSArchitecture = 'X64'
                                                                                                        }
                                                                                                  }

                                                                                                $DriverPackDownloadProperties.DriverPackReleaseID = "$($DriverPackSearchResult.ID.ToUpper())"
                                                                                                $DriverPackDownloadProperties.DriverPackReleaseVersion = "$($DriverPackSearchResult.Version)"
                                                                                                $DriverPackDownloadProperties.DriverPackReleaseDate = Try {(Get-Date -Date $DriverPackSearchResult.DateReleased).ToString($DateDriverPackReleaseFormat)} Catch {$DriverPackSearchResult.DateReleased}
                                                                                                $DriverPackDownloadProperties.DriverPackInfoURL = "$($DriverPackSearchResult.ReleaseNotesURL)"
                                                                                                $DriverPackDownloadProperties.DirectoryPath = "$($DriverPackDownloadProperties.Manufacturer)\$($DriverPackDownloadProperties.BaseboardProduct)\$($DriverPackDownloadProperties.OSAlias)\$($DriverPackDownloadProperties.OSArchitecture)"

                                                                                                Switch ($Null -ine $DriverPackOSDetails)
                                                                                                  {
                                                                                                      {($_ -eq $True)}
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.FileBaseName = "$($DriverPackDownloadProperties.Manufacturer)-$($DriverPackDownloadProperties.BaseboardProduct)-$($DriverPackDownloadProperties.DriverPackReleaseID)-$($DriverPackDownloadProperties.OSAlias)-$($DriverPackDownloadProperties.OSArchitecture)-$($DriverPackDownloadProperties.OSReleaseIDMinimum)"
                                                                                                        }

                                                                                                      Default
                                                                                                        {
                                                                                                            $DriverPackDownloadProperties.FileBaseName = "$($DriverPackDownloadProperties.Manufacturer)-$($DriverPackDownloadProperties.BaseboardProduct)-$($DriverPackDownloadProperties.DriverPackReleaseID)-$($DriverPackDownloadProperties.OSAlias)-$($DriverPackDownloadProperties.OSArchitecture)"
                                                                                                        }
                                                                                                  }

                                                                                                $DriverPackDownloadProperties.FileBaseName = $DriverPackDownloadProperties.FileBaseName.Split([System.IO.Path]::GetInvalidFileNameChars()) -Join ''
     
                                                                                                $DriverPackDownloadProperties.FileName = "$($DriverPackDownloadProperties.FileBaseName).wim"
                                                                                                $DriverPackDownloadProperties.FilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.FileName)"
                                                                                                $DriverPackDownloadProperties.MetadataFileName = "$($DriverPackDownloadProperties.FileBaseName).json"
                                                                                                $DriverPackDownloadProperties.MetadataFilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.MetadataFileName)"
                                                                                                $DriverPackDownloadProperties.DownloadLinkList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                  $DriverPackDownloadProperties.DownloadLinkList.DriverPack = "$($DriverPackSearchResult.URL)"
                                                                                                  $DriverPackDownloadProperties.DownloadLinkList.DriverPackMetadata = "$($DriverPackSearchResult.CVAFileURL)"

                                                                                              $DriverPackDownloadObject = New-Object -TypeName 'PSObject' -Property ($DriverPackDownloadProperties)

                                                                                              $DriverPackDownloadList.Add($DriverPackDownloadObject)
                                                                                          }
                                                                                    }
                                                                              }
                                                                        }

                                                                      {($_ -iin @('Lenovo'))}
                                                                        {
                                                                            $ModelID = [Regex]::Match($Model.ProductID, '^\w{4}')

                                                                            Switch ($ModelID.Success)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        $DriverPackSearchResults = New-Object -TypeName 'System.Collections.Generic.List[Object]'

                                                                                        $CatalogSearchResults = $DriverPackCatalog.SelectNodes('/ModelList/Model') | Where-Object {($_.Types.Type -icontains $ModelID.Value)}

                                                                                        ForEach ($CatalogSearchResult In $CatalogSearchResults)
                                                                                          {
                                                                                              $CatalogSearchURLList = $CatalogSearchResult.SCCM | Where-Object {($_.OS -imatch $OperatingSystemEntry.NameExpression) -and ($_.Version -imatch $OperatingSystemEntry.ReleaseExpression)}

                                                                                              ForEach ($CatalogSearchURL In $CatalogSearchURLList)
                                                                                                {
                                                                                                    $CatalogSearchMetadataParser = [Regex]::Match($CatalogSearchURL.'#text', '.*(?<OperatingSystemName>w\d{1,2})(?<OperatingSystemArchitecture>\d{2,2})?.*(?<DateReleased>\d{6,8}).*')

                                                                                                    Switch ($CatalogSearchMetadataParser.Success)
                                                                                                      {
                                                                                                          {($_ -eq $True)}
                                                                                                            {
                                                                                                                $CatalogSearchResultProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                                  $CatalogSearchResultProperties.Name = $CatalogSearchResult.Name -ireplace '\s+Type.*', ''
                                                                                                                  $CatalogSearchResultProperties.SystemTypeList = $CatalogSearchResult.Types.Type
                                                                                                                  $CatalogSearchResultProperties.OperatingSystemRelease = $CatalogSearchURL.Version

                                                                                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to parse metadata for `"$($CatalogSearchResultProperties.Name)`" from URL `"$($CatalogSearchMetadataParser.ToString())`". Please Wait..."
                                                                                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                                                ForEach ($CatalogSearchMetadataCaptureGroup In ($CatalogSearchMetadataParser.Groups | Where-Object {($_.Name -inotin @('0'))}))
                                                                                                                  {
                                                                                                                      Switch (([String]::IsNullOrEmpty($CatalogSearchMetadataCaptureGroup.Value) -eq $False) -or ([String]::IsNullOrWhiteSpace($CatalogSearchMetadataCaptureGroup.Value) -eq $False))
                                                                                                                        {
                                                                                                                            {($_ -eq $True)}
                                                                                                                              {
                                                                                                                                  Switch ($CatalogSearchMetadataCaptureGroup.Name)
                                                                                                                                    {
                                                                                                                                        {($_ -iin @('DateReleased'))}
                                                                                                                                          {
                                                                                                                                              Switch ($CatalogSearchMetadataCaptureGroup.Success)
                                                                                                                                                {
                                                                                                                                                    {($_ -eq $True)}
                                                                                                                                                      {
                                                                                                                                                          $DateTimeFormatList = New-Object -TypeName 'System.Collections.Generic.List[String]' 
                                                                                                                                                            $DateTimeFormatList.Add('yyyyMM')

                                                                                                                                                          $DateTime = New-Object -TypeName 'DateTime'

                                                                                                                                                          $DateTimeTryParseExactProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                                                                            $DateTimeTryParseExactProperties.Input = $CatalogSearchMetadataCaptureGroup.Value
                                                                                                                                                            $DateTimeTryParseExactProperties.FormatList = $DateTimeFormatList.ToArray()
                                                                                                                                                            $DateTimeTryParseExactProperties.Styles = New-Object -TypeName 'System.Collections.Generic.List[System.Globalization.DateTimeStyles]'
                                                                                                                                                              $DateTimeTryParseExactProperties.Styles.Add([System.Globalization.DateTimeStyles]::AssumeUniversal)
                                                                                                                                                              $DateTimeTryParseExactProperties.Styles.Add([System.Globalization.DateTimeStyles]::AllowWhiteSpaces)
                                                                                                                                                            $DateTimeTryParseExactProperties.DateTime = $Null
                                                                                                                                                            $DateTimeTryParseExactProperties.Successful = [DateTime]::TryParseExact($DateTimeTryParseExactProperties.Input, $DateTimeTryParseExactProperties.FormatList, $DateTimeTryParseExactProperties.Culture, $DateTimeTryParseExactProperties.Styles, [Ref]$DateTime)

                                                                                                                                                          Switch ($DateTimeTryParseExactProperties.Successful)
                                                                                                                                                            {
                                                                                                                                                                {($_ -eq $True)}
                                                                                                                                                                  {
                                                                                                                                                                      $DateTimeTryParseExactProperties.DateTime = ($DateTime)
                                                                                                                                                                  }
                                                                                                                                                            }

                                                                                                                                                          $DateTimeTryParseExactObject = New-Object -TypeName 'PSObject' -Property ($DateTimeTryParseExactProperties)

                                                                                                                                                          $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = $DateTimeTryParseExactObject.DateTime
                                                                                                                                                      }

                                                                                                                                                    Default
                                                                                                                                                      {
                                                                                                                                                          $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = $CatalogSearchMetadataCaptureGroup.Value
                                                                                                                                                      }
                                                                                                                                                }
                                                                                                                                          }

                                                                                                                                        {($_ -iin @('OperatingSystemArchitecture'))}
                                                                                                                                          {
                                                                                                                                              Switch ($True)
                                                                                                                                                {
                                                                                                                                                    {($CatalogSearchMetadataCaptureGroup.Value -inotmatch '^X')}
                                                                                                                                                      {
                                                                                                                                                          $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = "X$($CatalogSearchMetadataCaptureGroup.Value)"
                                                                                                                                                      }
                                                                                                                                                }
                                                                                                                                          }

                                                                                                                                        Default
                                                                                                                                          {
                                                                                                                                              $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = $CatalogSearchMetadataCaptureGroup.Value
                                                                                                                                          }
                                                                                                                                    }
                                                                                                                              }

                                                                                                                            Default
                                                                                                                              {
                                                                                                                                  Switch ($CatalogSearchMetadataCaptureGroup.Name)
                                                                                                                                    {
                                                                                                                                        {($_ -iin @('OperatingSystemArchitecture'))}
                                                                                                                                          {
                                                                                                                                              $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = 'X64'
                                                                                                                                          }

                                                                                                                                        Default
                                                                                                                                          {
                                                                                                                                              $CatalogSearchResultProperties.$($CatalogSearchMetadataCaptureGroup.Name) = $Null
                                                                                                                                          }
                                                                                                                                    }
                                                                                                                              }
                                                                                                                        }
                                                                                                                  }

                                                                                                                $CatalogSearchResultProperties.URL = $CatalogSearchURL.'#text'

                                                                                                                $CatalogSearchResultObject = New-Object -TypeName 'PSObject' -Property ($CatalogSearchResultProperties)

                                                                                                                $DriverPackSearchResults.Add($CatalogSearchResultObject)
                                                                                                            }

                                                                                                          Default
                                                                                                            {
                                                                                                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Unable to parse metadata for `"$($CatalogSearchResultProperties.Name)`" from URL `"$($CatalogSearchMetadataParser.ToString())`". Skipping..."
                                                                                                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                                            }
                                                                                                      }
                                                                                                }
                                                                                          }

                                                                                        $DriverPackSearchResultCount = ($DriverPackSearchResults | Measure-Object).Count

                                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchResultCount) result(s) were returned from the driver pack search."
                                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                        Switch ($OperatingSystemEntry.LatestReleaseOnly)
                                                                                          {
                                                                                              {($_ -eq $True)}
                                                                                                {
                                                                                                    $DriverPackSearchFilteredResults = $DriverPackSearchResults | Select-Object -Last 1
                                                                                                }

                                                                                              Default
                                                                                                {
                                                                                                    $DriverPackSearchFilteredResults = $DriverPackSearchResults
                                                                                                }
                                                                                          }
         
                                                                                        $DriverPackSearchFilteredResultCount = ($DriverPackSearchFilteredResults | Measure-Object).Count

                                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackSearchFilteredResultCount) result(s) remain after filtering, and sorting."
                                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                        Switch ($DriverPackSearchFilteredResultCount -gt 0)
                                                                                          {
                                                                                              {($_ -eq $True)}
                                                                                                {
                                                                                                    ForEach ($DriverPackSearchResult In $DriverPackSearchFilteredResults)
                                                                                                      {
                                                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add driver pack for `"$($DriverPackSearchResult.Name)`" released on $($DriverPackSearchResult.DateReleased.ToString($DateTimeLogFormat)). Please Wait..."
                                                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                                          $DriverPackDownloadProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                            $DriverPackDownloadProperties.Enabled = $True
                                                                                                            $DriverPackDownloadProperties.Manufacturer = $Manufacturer.Name
                                                                                                            $DriverPackDownloadProperties.BaseboardProduct = $Model.BaseboardProduct
                                                                                                            $DriverPackDownloadProperties.SystemFamily = $Model.SystemFamily
                                                                                                            $DriverPackDownloadProperties.SystemManufacturer = $Model.SystemManufacturer
                                                                                                            $DriverPackDownloadProperties.SystemProductName = $Model.SystemProductName
                                                                                                            $DriverPackDownloadProperties.SystemSKU = $Model.SystemSKU
                                                                                                            $DriverPackDownloadProperties.SystemVersion = $Model.SystemVersion
                                                                                                            $DriverPackDownloadProperties.ProductIDList = $CatalogSearchResultProperties.SystemTypeList
                                                                                                            $DriverPackDownloadProperties.ProductID = $DriverPackDownloadProperties.ProductIDList[0]
                                                                                                            $DriverPackDownloadProperties.OSName = "$($OperatingSystemEntry.Name)"
                                                                                                            $DriverPackDownloadProperties.OSAlias = "W$($OperatingSystemEntry.Name -ireplace '(\D+)', '')"

                                                                                                            $DriverPackOSDetails = $OperatingSystemEntryReleaseHistory | Where-Object {($_.ReleaseID -ieq [Regex]::Match($DriverPackSearchResult.OperatingSystemRelease, $_.ReleaseID).Value)} | Select-Object -First 1

                                                                                                            Switch ($Null -ine $DriverPackOSDetails)
                                                                                                              {
                                                                                                                  {($_ -eq $True)}
                                                                                                                    {
                                                                                                                        $DriverPackDownloadProperties.OSVersionMinimum = $DriverPackOSDetails.Version.ToString()

                                                                                                                        $DriverPackDownloadProperties.OSReleaseIDMinimum = $DriverPackOSDetails.ReleaseID
                                                                                                                    }
            
                                                                                                                  Default
                                                                                                                    {
                                                                                                                        $DriverPackDownloadProperties.OSVersionMinimum = $OperatingSystemEntryVersion.ToString()

                                                                                                                        $DriverPackDownloadProperties.OSReleaseIDMinimum = "All"
                                                                                                                    }
                                                                                                              }

                                                                                                            $DriverPackDownloadProperties.OSArchitecture = $DriverPackSearchResult.OperatingSystemArchitecture
                                                                                                            
                                                                                                            Switch ($Null -ine $DriverPackOSDetails)
                                                                                                              {
                                                                                                                  {($_ -eq $True)}
                                                                                                                    {
                                                                                                                        $DriverPackDownloadProperties.DriverPackReleaseID = $DriverPackOSDetails.ReleaseID
                                                                                                                    }
            
                                                                                                                  Default
                                                                                                                    {
                                                                                                                        $DriverPackDownloadProperties.DriverPackReleaseID = 'NA'
                                                                                                                    }
                                                                                                              }

                                                                                                            $DriverPackDownloadProperties.DriverPackReleaseVersion = 'NA'
                                                                                                            $DriverPackDownloadProperties.DriverPackReleaseDate = Try {(Get-Date -Date $DriverPackSearchResult.DateReleased).ToString($DateDriverPackReleaseFormat)} Catch {$DriverPackSearchResult.DateReleased} 
                                                                                                            $DriverPackDownloadProperties.DriverPackInfoURL = ""
                                                                                                            $DriverPackDownloadProperties.DirectoryPath = "$($DriverPackDownloadProperties.Manufacturer)\$($ModelID.Value)\$($DriverPackDownloadProperties.OSAlias)\$($DriverPackDownloadProperties.OSArchitecture)"
                                                                                                            $DriverPackDownloadProperties.FileBaseName = "$($DriverPackDownloadProperties.Manufacturer)-$($ModelID.Value)-$($DriverPackDownloadProperties.OSAlias)-$($DriverPackDownloadProperties.OSArchitecture)-$($DriverPackDownloadProperties.OSReleaseIDMinimum)"

                                                                                                            $DriverPackDownloadProperties.FileBaseName = $DriverPackDownloadProperties.FileBaseName.Split([System.IO.Path]::GetInvalidFileNameChars()) -Join ''

                                                                                                            $DriverPackDownloadProperties.FileName = "$($DriverPackDownloadProperties.FileBaseName).wim"
                                                                                                            $DriverPackDownloadProperties.FilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.FileName)"
                                                                                                            $DriverPackDownloadProperties.MetadataFileName = "$($DriverPackDownloadProperties.FileBaseName).json"
                                                                                                            $DriverPackDownloadProperties.MetadataFilePath = "$($DriverPackDownloadProperties.DirectoryPath)\$($DriverPackDownloadProperties.MetadataFileName)"
                                                                                                            $DriverPackDownloadProperties.DownloadLinkList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                              $DriverPackDownloadProperties.DownloadLinkList.DriverPack = "$($DriverPackSearchResult.URL)"
                                                                                                              $DriverPackDownloadProperties.DownloadLinkList.DriverPackMetadata = ""

                                                                                                          $DriverPackDownloadObject = New-Object -TypeName 'PSObject' -Property ($DriverPackDownloadProperties)

                                                                                                          $DriverPackDownloadList.Add($DriverPackDownloadObject)
                                                                                                      }
                                                                                                }
                                                                                          }
                                                                                    }

                                                                                  Default
                                                                                    {
                                                                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Unable to parse metadata for `"$($CatalogSearchResultProperties.Name)`" from URL `"$($CatalogSearchMetadataParser.ToString())`". Skipping..."
                                                                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                    }
                                                                              }
                                                                        }
                                                                  }
                                                            }
                                                      }

                                                    {($_ -eq $False)}
                                                      {
                                                          $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The XML node for model `"$($Model.SystemProductName)`" manufactured by `"$($Model.SystemManufacturer)`" is not enabled. Skipping..."
                                                          Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                      }
                                                }
                                          }
                                    }

                                  {($_ -eq $False)}
                                    {
                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The XML node for device manufacturer `"$($Manufacturer.Name)`" is not enabled. Skipping..."
                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                    }
                              }
                        }
                      Catch
                        {
                            $ErrorMessageList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                              $ErrorMessageList.Add('Message', $_.Exception.Message)
                              $ErrorMessageList.Add('Category', $_.Exception.ErrorRecord.FullyQualifiedErrorID)
                              $ErrorMessageList.Add('Script', $_.InvocationInfo.ScriptName)
                              $ErrorMessageList.Add('LineNumber', $_.InvocationInfo.ScriptLineNumber)
                              $ErrorMessageList.Add('LinePosition', $_.InvocationInfo.OffsetInLine)
                              $ErrorMessageList.Add('Code', $_.InvocationInfo.Line.Trim())

                            ForEach ($ErrorMessage In $ErrorMessageList.GetEnumerator())
                              {
                                  $LoggingDetails.ErrorMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  ERROR: $($ErrorMessage.Key): $($ErrorMessage.Value)"
                                  Write-Warning -Message ($LoggingDetails.ErrorMessage) -Verbose
                              }
                        }
                      Finally
                        {

                        }
                  }

                Switch ($DisableDownload)
                  {
                      {($_ -eq $True)}
                        {
                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The downloading and processing of driver pack(s) is disabled! Please remove the '-DisableDownload' parameter to enable downloading."
                            Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                        }

                      Default
                        {
                            Try
                              {
                                  $DriverPackDownloadList = $DriverPackDownloadList.ToArray()

                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A total of $($DriverPackDownloadList.Count) driver pack download(s) will be processed. Please Wait..."
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                  #Process Driver Pack Downloads
                                    $ManufacturerGroupList = $DriverPackDownloadList | Group-Object -Property @('Manufacturer') | Sort-Object -Property @('Name')

                                    :ManufacturerGroupLoop ForEach ($ManufacturerGroup In $ManufacturerGroupList)
                                      {
                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process $($ManufacturerGroup.Count) manufacturer specific download(s) for manufacturer `"$($ManufacturerGroup.Name)`". Please Wait..."
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                          $ProductGroupProperty = 'ProductID'

                                          $ProductGroupAliasProperty = 'SystemProductName'

                                          Switch ($ManufacturerGroup.Name)
                                            {
                                                {($_ -iin @('Lenovo'))}
                                                  {
                                                      $ProductGroupAliasProperty = 'SystemVersion'
                                                  }
                                            }

                                          $ProductGroupList = $ManufacturerGroup.Group | Group-Object -Property ($ProductGroupProperty) | Sort-Object -Property @('Name')

                                          :ProductGroupLoop ForEach ($ProductGroup In $ProductGroupList)
                                            {
                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process $($ProductGroup.Count) product ID specific download(s) for product ID `"$($ProductGroup.Name)`" manufactured by `"$($ManufacturerGroup.Name)`". Please Wait..."
                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                :ProductGroupMemberLoop ForEach ($ProductGroupMember In $ProductGroup.Group)
                                                  {
                                                      $NewWindowsImageDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                        $NewWindowsImageDetails.ImageStagingPath = "$($LocalDriverPackageDirectory.FullName)\$($ProductGroupMember.DirectoryPath)\$($ProductGroupMember.FileName)" -As [System.IO.FileInfo]
                                                        $NewWindowsImageDetails.ImageFinalPath = $NewWindowsImageDetails.ImageStagingPath.FullName.Replace($LocalDriverPackageDirectory.FullName, $DriverPackageDirectory.FullName) -As [System.IO.FileInfo]
                                                        $NewWindowsImageDetails.LogPath = "$($LogDirectory.FullName)\DISM\$($ManufacturerGroup.Name)\$($ProductGroupMember.$($ProductGroupProperty))\$($NewWindowsImageDetails.ImageStagingPath.BaseName).log" -As [System.IO.FileInfo]
                                                    
                                                      Switch (([System.IO.File]::Exists($NewWindowsImageDetails.ImageFinalPath.FullName) -eq $False) -or ($Force -eq $True))
                                                        {
                                                            {($_ -eq $True)}
                                                              {
                                                                  Switch (([System.IO.File]::Exists($NewWindowsImageDetails.ImageStagingPath.FullName) -eq $False) -or ($Force -eq $True))
                                                                    {
                                                                        {($_ -eq $True)}
                                                                          {
                                                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process the `"$($ProductGroupMember.OSName) $($ProductGroupMember.OSArchitecture)`" download list for product ID `"$($ProductGroup.Name)`" [Model: $($ProductGroupMember.$($ProductGroupAliasProperty))] manufactured by `"$($ManufacturerGroup.Name)`". Please Wait..."
                                                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                                                                              :ProductGroupMemberDownloadLoop ForEach ($ProductGroupMemberDownload In $ProductGroupMember.DownloadLinkList.GetEnumerator())
                                                                                {
                                                                                    Switch (([String]::IsNullOrEmpty($ProductGroupMemberDownload.Value) -eq $False) -and ([String]::IsNullOrWhiteSpace($ProductGroupMemberDownload.Value) -eq $False))
                                                                                      {
                                                                                          {($_ -eq $True)}
                                                                                            {
                                                                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process the URL for `"$($ProductGroupMemberDownload.Key)`". Please Wait..."
                                                                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                                                                                                Switch ($ProductGroupMemberDownload.Key)
                                                                                                  {
                                                                                                      {($_ -iin @('DriverPack'))}
                                                                                                        {
                                                                                                            $InvokeFileDownloadParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                              $InvokeFileDownloadParameters.URL = $ProductGroupMemberDownload.Value
                                                                                                              $InvokeFileDownloadParameters.Destination = "$($DownloadDirectory.FullName)\$($ProductGroupMember.Manufacturer)\$($ProductGroupMember.$($ProductGroupProperty))"
                                                                                                              $InvokeFileDownloadParameters.ContinueOnError = $False
                                                                                                              $InvokeFileDownloadParameters.Verbose = $True
                        
                                                                                                            $InvokeFileDownloadResult = Invoke-FileDownloadWithProgress @InvokeFileDownloadParameters
                        
                                                                                                            $FileDownloadExtractionParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                              $FileDownloadExtractionParameters.ExtractionPath = "$($DownloadDirectory.FullName)\$($ProductGroupMember.Manufacturer)\$($ProductGroupMember.$($ProductGroupProperty))\$($ProductGroupMember.OSAlias)-$($ProductGroupMember.OSArchitecture)-$($ProductGroupMember.DriverPackReleaseID)" -As [System.IO.DirectoryInfo]
                                                                                                              $FileDownloadExtractionParameters.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                                                                              $FileDownloadExtractionParameters.CopyDriverPackMetadata = $True
                                                                                                              $FileDownloadExtractionParameters.CreateWindowsImageDriverPack = $True
                        
                                                                                                            Switch ($ProductGroupMember.Manufacturer)
                                                                                                              {
                                                                                                                  {($_ -iin @('Lenovo'))}
                                                                                                                    {
                                                                                                                        $FileDownloadExtractionParameters.FilePath = $InvokeFileDownloadResult.DownloadPath.FullName -As [System.IO.FileInfo]
                          
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("/VERYSILENT")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("/DIR=`"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`"")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("/EXTRACT=`"YES`"")
                                                                                                                    }
                          
                                                                                                                  Default
                                                                                                                    {
                                                                                                                        $FileDownloadExtractionParameters.FilePath = $7ZipPath.FullName -As [System.IO.FileInfo]
                          
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("x")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("`"$($InvokeFileDownloadResult.DownloadPath.FullName)`"")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("-o`"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`"")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("*")
                                                                                                                        $FileDownloadExtractionParameters.ArgumentList.Add("-r")
                                                                                                                    }
                                                                                                              }
                        
                                                                                                            Switch ([System.IO.Directory]::Exists($FileDownloadExtractionParameters.ExtractionPath.FullName))
                                                                                                              {
                                                                                                                  {($_ -eq $True)}
                                                                                                                    {
                                                                                                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove existing directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`" prior to extraction. Please Wait..."
                                                                                                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                          
                                                                                                                        [String]$DeletionPath = $FileDownloadExtractionParameters.ExtractionPath.FullName
                                                                                      
                                                                                                                        $Null = [Alphaleonis.Win32.Filesystem.Directory]::Delete($DeletionPath, $True, $True)
                                                                                                                    }
                                                                                                              }

                                                                                                            Switch ($ProductGroupMember.Manufacturer)
                                                                                                              {
                                                                                                                  {($_ -inotin @('Lenovo'))}
                                                                                                                    {
                                                                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create non-existent directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`" prior to extraction. Please Wait..."
                                                                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                                                                                                                        $Null = [System.IO.Directory]::CreateDirectory($FileDownloadExtractionParameters.ExtractionPath.FullName)
                                                                                                                    }
                                                                                                              }
                        
                                                                                                            $StartProcessWithOutputParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                              $StartProcessWithOutputParameters.FilePath = $FileDownloadExtractionParameters.FilePath.FullName
                                                                                                              $StartProcessWithOutputParameters.ArgumentList = $FileDownloadExtractionParameters.ArgumentList
                                                                                                              $StartProcessWithOutputParameters.AcceptableExitCodeList = @(0, 3010)
                                                                                                              $StartProcessWithOutputParameters.CreateNoWindow = $True
                                                                                                              $StartProcessWithOutputParameters.LogOutput = $False
                                                                                                              $StartProcessWithOutputParameters.Verbose = $True
                          
                                                                                                            $FileDownloadExtractionResult = Start-ProcessWithOutput @StartProcessWithOutputParameters
                        
                                                                                                            Switch ($FileDownloadExtractionParameters.ExtractionPath.GetDirectories().Count -gt 2)
                                                                                                              {
                                                                                                                  {($_ -eq $True)}
                                                                                                                    {
                                                                                                                        $WindowsImageRootFolder = $FileDownloadExtractionParameters.ExtractionPath
                                                                                                                    }
                          
                                                                                                                  Default
                                                                                                                    {
                                                                                                                        $WindowsImageRootFolderList = Get-ChildItem -Path ($FileDownloadExtractionParameters.ExtractionPath.FullName) -Recurse | Where-Object {($_ -is [System.IO.DirectoryInfo]) -and ($_.GetDirectories().Count -gt 2)}
                          
                                                                                                                        Switch ($Null -ine $WindowsImageRootFolderList)
                                                                                                                          {
                                                                                                                              {($_ -eq $True)}
                                                                                                                                {
                                                                                                                                    $WindowsImageRootFolder = $WindowsImageRootFolderList | Sort-Object -Property @{Expression = {($_.FullName.Length)}} | Select-Object -First 1
                                                                                                                                }
                          
                                                                                                                              {($_ -eq $False)}
                                                                                                                                {
                                                                                                                                    $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The windows image root folder could not located within folder `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`"."
                                                                                                                                    Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                          
                                                                                                                                    $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Cleaning up and moving to the next driver pack. Please Wait..."
                                                                                                                                    Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                          
                                                                                                                                    $FileDownloadExtractionParameters.CopyDriverPackMetadata = $False
                          
                                                                                                                                    $FileDownloadExtractionParameters.CreateWindowsImageDriverPack = $False
                          
                                                                                                                                    $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove driver pack extraction directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`". Please Wait..."
                                                                                                                                    Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                          
                                                                                                                                    #Cleanup the extracted driver package content (If necessary)
                                                                                                                                      If ([System.IO.Directory]::Exists($FileDownloadExtractionParameters.ExtractionPath.FullName) -eq $True)
                                                                                                                                        {
                                                                                                                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove driver pack extraction directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`". Please Wait..."
                                                                                                                                            Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                                                                          
                                                                                                                                            [String]$DeletionPath = $FileDownloadExtractionParameters.ExtractionPath.FullName
            
                                                                                                                                            $Null = [Alphaleonis.Win32.Filesystem.Directory]::Delete($DeletionPath, $True, $True)
                                                                                                                                        }
                          
                                                                                                                                    Break ProductGroupMemberLoop
                                                                                                                                }
                                                                                                                          }
                                                                                                                    }
                                                                                                              }
                                                                                                        }
                        
                                                                                                      {($_ -iin @('DriverPackMetaData'))}
                                                                                                        {
                                                                                                            Switch ($FileDownloadExtractionParameters.CopyDriverPackMetadata)
                                                                                                              {
                                                                                                                  {($_ -eq $True)}
                                                                                                                    {
                                                                                                                        $DriverPackMetaDataFileList = New-Object -TypeName 'System.Collections.Generic.List[System.IO.FileInfo]'
                        
                                                                                                                        $DriverPackMetaDataExtensionList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                                                                                          $DriverPackMetaDataExtensionList.Add('.xml')
                                                                                                                          $DriverPackMetaDataExtensionList.Add('.html')
                                                                                                                          $DriverPackMetaDataExtensionList.Add('.cva')
                                                                                                                          $DriverPackMetaDataExtensionList.Add('.json')
                                                                                                                          $DriverPackMetaDataExtensionList.Add('.txt')
                        
                                                                                                                          $DriverPackMetaDataFiles = Get-ChildItem -Path "$($FileDownloadExtractionParameters.ExtractionPath.FullName)\" -Depth 1 -Force -ErrorAction SilentlyContinue | Where-Object {($_ -is [System.IO.FileInfo]) -and ($_.Extension -iin $DriverPackMetaDataExtensionList.ToArray())}
                        
                                                                                                                          $DriverPackMetaDataFileCount = ($DriverPackMetaDataFiles | Measure-Object).Count
                        
                                                                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackMetaDataFileCount) metadata file(s) matching `"$($DriverPackMetaDataExtensionList -Join ' | ')`" were found in directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`"."
                                                                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                                                                                                                          Switch ($DriverPackMetaDataFileCount -gt 0)
                                                                                                                            {
                                                                                                                                {($_ -eq $True)}
                                                                                                                                  {
                                                                                                                                      $DriverPackMetaDataFiles | ForEach-Object {$DriverPackMetaDataFileList.Add($_.FullName)}
                                                                                                                                  }
                                                                                                                            }
                        
                                                                                                                          [System.IO.DirectoryInfo]$DriverPackMetaDataDirectory = "$($WindowsImageRootFolder.FullName)\Metadata"
                        
                                                                                                                          If ([System.IO.Directory]::Exists($DriverPackMetaDataDirectory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DriverPackMetaDataDirectory.FullName)}
                        
                                                                                                                          ForEach ($DriverPackMetaDataFile In $DriverPackMetaDataFileList)
                                                                                                                            {
                                                                                                                                [System.IO.FileInfo]$DriverPackMetaDataFileDestination = "$($DriverPackMetaDataDirectory.FullName)\$($DriverPackMetaDataFile.Name)"
                        
                                                                                                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to copy metadata file `"$($DriverPackMetaDataFile.FullName)`" to `"$($DriverPackMetaDataFileDestination.FullName)`". Please Wait..."
                                                                                                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                        
                                                                                                                                $Null = [System.IO.File]::Copy($DriverPackMetaDataFile.FullName, $DriverPackMetaDataFileDestination.FullName, $True)
                                                                                                                            }
                        
                                                                                                                          $InvokeFileDownloadParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                                            $InvokeFileDownloadParameters.URL = $ProductGroupMemberDownload.Value
                                                                                                                            $InvokeFileDownloadParameters.Destination = "$($DownloadDirectory.FullName)\$($ProductGroupMember.Manufacturer)\$($ProductGroupMember.$($ProductGroupProperty))"
                                                                                                                            $InvokeFileDownloadParameters.ContinueOnError = $False
                                                                                                                            $InvokeFileDownloadParameters.Verbose = $True
                        
                                                                                                                          $InvokeFileDownloadResult = Invoke-FileDownloadWithProgress @InvokeFileDownloadParameters
                        
                                                                                                                          $Null = [System.IO.File]::Copy($InvokeFileDownloadResult.DownloadPath.FullName, "$($DriverPackMetaDataFileDestination.Directory.FullName)\$($InvokeFileDownloadResult.DownloadPath.Name)", $True)
                                                                                                                    }
                                                                                                              }
                                                                                                        }
                        
                                                                                                      Default
                                                                                                        {
                                                                                                            $InvokeFileDownloadParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                              $InvokeFileDownloadParameters.URL = $ProductGroupMemberDownload.Value
                                                                                                              $InvokeFileDownloadParameters.Destination = $FileDownloadExtractionParameters.ExtractionPath.FullName
                                                                                                              $InvokeFileDownloadParameters.ContinueOnError = $False
                                                                                                              $InvokeFileDownloadParameters.Verbose = $True
                        
                                                                                                            $InvokeFileDownloadResult = Invoke-FileDownloadWithProgress @InvokeFileDownloadParameters
                                                                                                        }
                                                                                                  }
                                                                                            }
                        
                                                                                          Default
                                                                                            {
                                                                                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The `"$($ProductGroupMemberDownload.Key)`" URL will not be processed because the value does not contain any data. Please Wait..."
                                                                                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                            }
                                                                                      }
                                                                                }
                      
                                                                              #Create a windows image from the driver content if one does not already exist
                                                                                Switch ([System.IO.File]::Exists($NewWindowsImageDetails.ImageStagingPath.FullName))
                                                                                  {
                                                                                      {($_ -eq $True)}
                                                                                        {
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The windows image file `"$($NewWindowsImageDetails.ImageStagingPath.FullName)`" already exists and will not be created. Skipping."
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                                        }
                                                                                    
                                                                                      {($_ -eq $False)}
                                                                                        {
                                                                                            Switch ($True)
                                                                                              {
                                                                                                  {([System.IO.Directory]::Exists($NewWindowsImageDetails.ImageStagingPath.Directory.FullName) -eq $False)}
                                                                                                    {
                                                                                                        $Null = [System.IO.Directory]::CreateDirectory($NewWindowsImageDetails.ImageStagingPath.Directory.FullName)
                                                                                                    }
                      
                                                                                                  {([System.IO.Directory]::Exists($NewWindowsImageDetails.LogPath.Directory.FullName) -eq $False)}
                                                                                                    {
                                                                                                        $Null = [System.IO.Directory]::CreateDirectory($NewWindowsImageDetails.LogPath.Directory.FullName)
                                                                                                    }
                                                                                              }
                      
                                                                                            $NewWindowsImageParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                              $NewWindowsImageParameters.CapturePath = $WindowsImageRootFolder.FullName
                                                                                              $NewWindowsImageParameters.ImagePath = $NewWindowsImageDetails.ImageStagingPath.FullName
                                                                                              $NewWindowsImageParameters.Name = $ProductGroupMember.FileBaseName
                                                                                              $NewWindowsImageParameters.Description = $ProductGroupMember | Select-Object -Property @('*') -ExcludeProperty @('Enabled') | ConvertTo-JSON -Depth 10 -Compress:$True
                                                                                              $NewWindowsImageParameters.CompressionType = 'Max'
                                                                                              $NewWindowsImageParameters.Verify = $False
                                                                                              $NewWindowsImageParameters.LogPath = $NewWindowsImageDetails.LogPath.FullName
                                                                                              $NewWindowsImageParameters.LogLevel = 'WarningsInfo'
                                                                                              $NewWindowsImageParameters.Verbose = $False
                      
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to compress the extracted content for the `"$($ProductGroupMember.OSName) $($ProductGroupMember.OSArchitecture)`" driver pack `"$($ProductGroupMember.DriverPackReleaseID)`" for product ID `"$($ProductGroupMember.BaseboardProduct)`" [Model: $($ProductGroupMember.$($ProductGroupAliasProperty))] manufactured by `"$($ManufacturerGroup.Name)`" into the windows image format. Please Wait..."
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Capture Path: $($NewWindowsImageParameters.CapturePath)"
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Export Path: $($NewWindowsImageParameters.ImagePath)"
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Log Path: $($NewWindowsImageParameters.LogPath)"
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                            $CommandExecutionTimespan = Measure-Command -Expression {$Null = New-WindowsImage @NewWindowsImageParameters}
                      
                                                                                            If ($? -eq $True)
                                                                                              {
                                                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Extracted content compression completed in $($CommandExecutionTimespan.Hours.ToString()) hour(s), $($CommandExecutionTimespan.Minutes.ToString()) minute(s), $($CommandExecutionTimespan.Seconds.ToString()) second(s), and $($CommandExecutionTimespan.Milliseconds.ToString()) millisecond(s)."
                                                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                                  $NewWindowsImageDetails.HashDetails = Get-FileHash -Path ($NewWindowsImageParameters.ImagePath) -Algorithm ($HashAlgorithm)
                      
                                                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Hash: $($NewWindowsImageDetails.HashDetails.Hash) [Algorithm: $($NewWindowsImageDetails.HashDetails.Algorithm)]"
                                                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                                  $ExtractedContentSize = Get-ChildItem -Path "$($NewWindowsImageParameters.CapturePath)\*" -Recurse | Where-Object {($_ -is [System.IO.FileInfo])} | Measure-Object -Property @('Length') -Sum | Select-Object -ExpandProperty 'Sum'
                                                                                                  $ExtractedContentSizeDetails = Convert-FileSize -Size ($ExtractedContentSize) -DecimalPlaces 2
                      
                                                                                                  $WindowsImageDetails = Get-Item -Path ($NewWindowsImageParameters.ImagePath) -Force
                                                                                                  $WindowsImageDetailsSizeDetails = Convert-FileSize -Size ($WindowsImageDetails.Length) -DecimalPlaces 2
                      
                                                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The extracted content was reduced from its original size of $($ExtractedContentSizeDetails.CalculatedSizeStr) to its compressed size of $($WindowsImageDetailsSizeDetails.CalculatedSizeStr)."
                                                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                                  #Export the Windows image metadata
                                                                                                    $WindowsImageJSONTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                      $WindowsImageJSONTable.Cryptography = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                        $WindowsImageJSONTable.Cryptography.Hash = $NewWindowsImageDetails.HashDetails.Hash
                                                                                                        $WindowsImageJSONTable.Cryptography.Algorithm = $NewWindowsImageDetails.HashDetails.Algorithm
                                                                                                      $WindowsImageJSONTable.Content = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                        $WindowsImageJSONTable.Content.OriginalSize = $ExtractedContentSize
                                                                                                        $WindowsImageJSONTable.Content.CompressedSize = $WindowsImageDetails.Length
                                                                                                      $WindowsImageJSONTable.Metadata = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                        $WindowsImageJSONTable.Metadata = $ProductGroupMember | Select-Object -Property @('*') -ExcludeProperty @('Enabled', 'BaseboardProduct', 'SystemFamily', 'SystemManufacturer', 'SystemProductName', 'SystemSKU', 'SystemVersion', 'DirectoryPath', 'FileBaseName', 'FileName', 'MetadataFileName')
            
                                                                                                    $WindowsImageJSONContents = $WindowsImageJSONTable | ConvertTo-JSON -Depth 10 -Compress:$False
                      
                                                                                                    [System.IO.FileInfo]$WindowsImageJSONExportPath = "$($NewWindowsImageDetails.ImageStagingPath.Directory.FullName)\$($NewWindowsImageDetails.ImageStagingPath.BaseName).json"
                      
                                                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to export the driver package metadata to `"$($WindowsImageJSONExportPath.FullName)`". Please Wait..."
                                                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                                                                                                    If ([System.IO.Directory]::Exists($WindowsImageExportPath.Directory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($WindowsImageJSONExportPath.Directory.FullName)}
                      
                                                                                                    $Null = [System.IO.File]::WriteAllText($WindowsImageJSONExportPath.FullName, $WindowsImageJSONContents, [System.Text.Encoding]::Default)
                                                                                              }
                                                                                        }
                                                                                  }
                      
                                                                                #Cleanup the extracted driver package content (If necessary)
                                                                                  If ([System.IO.Directory]::Exists($FileDownloadExtractionParameters.ExtractionPath.FullName) -eq $True)
                                                                                    {
                                                                                        $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove driver pack extraction directory `"$($FileDownloadExtractionParameters.ExtractionPath.FullName)`". Please Wait..."
                                                                                        Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
            
                                                                                        [String]$DeletionPath = $FileDownloadExtractionParameters.ExtractionPath.FullName
                                                                                      
                                                                                        $Null = [Alphaleonis.Win32.Filesystem.Directory]::Delete($DeletionPath, $True, $True)
                                                                                    }
                                                                          }

                                                                        Default
                                                                          {
                                                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A driver pack staging windows image already exists for `"$($ProductGroupMember.OSName) $($ProductGroupMember.OSArchitecture)`" for product ID `"$($ProductGroup.Name)`" [Model: $($ProductGroupMember.$($ProductGroupAliasProperty))] manufactured by `"$($ManufacturerGroup.Name)`". Skipping..."
                                                                              Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
            
                                                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Staging Path: $($NewWindowsImageDetails.ImageStagingPath.FullName)"
                                                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                          }
                                                                    }     
                                                              }

                                                            Default
                                                              {
                                                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A driver pack windows image already exists for `"$($ProductGroupMember.OSName) $($ProductGroupMember.OSArchitecture)`" for product ID `"$($ProductGroup.Name)`" [Model: $($ProductGroupMember.$($ProductGroupAliasProperty))] manufactured by `"$($ManufacturerGroup.Name)`". Skipping..."
                                                                  Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Windows Image Path: $($NewWindowsImageDetails.ImageFinalPath.FullName)"
                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                              }
                                                        }       
                                                  }
                                            }
                                      }

                                  #Create the specified generic driver package folder(s)
                                    $GenericDriverPackageCategoryList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                      $GenericDriverPackageCategoryList.Add('Printers')
                                      $GenericDriverPackageCategoryList.Add('Docks')
                                      $GenericDriverPackageCategoryList.Add('Adapters')
                                      $GenericDriverPackageCategoryList.Add('Miscellaneous')
                                  
                                    $GenericDriverPackageFolderList = New-Object -TypeName 'System.Collections.Generic.List[System.IO.DirectoryInfo]'
                                      $GenericDriverPackageFolderList.Add("$($LocalDriverPackageDirectory.FullName)\Generic")

                                    $GenericDriverPackageTableList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                                    $Null = $GenericDriverPackageCategoryList.Sort()

                                    ForEach ($GenericDriverPackageCategory In $GenericDriverPackageCategoryList)
                                      {
                                          $GenericDriverPackageJSON = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                            $GenericDriverPackageJSON.Enabled = $False
                                            $GenericDriverPackageJSON.Metadata = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                              $GenericDriverPackageJSON.Metadata.Category = $GenericDriverPackageCategory
                                              $GenericDriverPackageJSON.Metadata.Name = "$($GenericDriverPackageFolderList[0].Name)-$($GenericDriverPackageCategory)"
                                              $GenericDriverPackageJSON.Metadata.ManufacturerInclusionExpression = '.*'
                                              $GenericDriverPackageJSON.Metadata.ManufacturerExclusionExpression = '(^.{0,0}$)'
                                              $GenericDriverPackageJSON.Metadata.ProductIDInclusionExpression = '.*'
                                              $GenericDriverPackageJSON.Metadata.ProductIDExclusionExpression = '(^.*Virtual.*$)'
                                              $GenericDriverPackageJSON.Metadata.OSVersionMinimum = ($WindowsReleaseHistory | Select-Object -First 1).Version.ToString()
                                              $GenericDriverPackageJSON.Metadata.OSArchitectureExpression = '.*'
                                              $GenericDriverPackageJSON.Metadata.FilePath = "$($GenericDriverPackageCategory)\$($GenericDriverPackageFolderList[0].Name)-$($GenericDriverPackageCategory).wim"
                                              $GenericDriverPackageJSON.Metadata.MetadataPath = "$($GenericDriverPackageCategory)\$($GenericDriverPackageFolderList[0].Name)-$($GenericDriverPackageCategory).json"

                                          $GenericDriverPackageTableProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                            $GenericDriverPackageTableProperties.Path = "$($GenericDriverPackageFolderList[0].FullName)\$($GenericDriverPackageJSON.Metadata.MetadataPath)" -As [System.IO.FileInfo]
                                            $GenericDriverPackageTableProperties.Contents = $GenericDriverPackageJSON | ConvertTo-JSON -Depth 10 -Compress:$False

                                          $GenericDriverPackageTableObject = New-Object -TypeName 'PSObject' -Property ($GenericDriverPackageTableProperties)
                                          
                                          $GenericDriverPackageTableList.Add($GenericDriverPackageTableObject)
                                      }
                                      
                                    ForEach ($GenericDriverPackageTable In $GenericDriverPackageTableList)
                                      {
                                          Switch ($True)
                                            {
                                                {([System.IO.Directory]::Exists($GenericDriverPackageTable.Path.Directory.FullName) -eq $False)}
                                                  {
                                                      $Null = [System.IO.Directory]::CreateDirectory($GenericDriverPackageTable.Path.Directory.FullName)
                                                  }           
                                            }

                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create JSON metadata file `"$($GenericDriverPackageTable.Path.FullName)`". Please Wait..."
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                          
                                          $Null = [System.IO.File]::WriteAllText($GenericDriverPackageTable.Path.FullName, $GenericDriverPackageTable.Contents, [System.Text.Encoding]::Default)
                                      }

                                  #Copy the locally created driver packages to the final destination     
                                    Switch ([System.IO.Directory]::Exists($LocalDriverPackageDirectory.FullName))
                                      {
                                          {($_ -eq $True)}
                                            {
                                                $LocalDriverPackageInclusionList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                  $LocalDriverPackageInclusionList.Add('*.wim')
                                                  $LocalDriverPackageInclusionList.Add('*.json')
                                              
                                                $LocalDriverPackages = Get-ChildItem -Path ($LocalDriverPackageDirectory.FullName) -Include ($LocalDriverPackageInclusionList.ToArray()) -Recurse -ErrorAction SilentlyContinue | Where-Object {($_ -is [System.IO.FileInfo])}
                                                
                                                $LocalDriverPackageCount = ($LocalDriverPackages | Measure-Object).Count
                                              
                                                Switch ($LocalDriverPackageCount -gt 0)
                                                  {
                                                      {($_ -eq $True)}
                                                        {
                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - There are $($LocalDriverPackageCount) windows image driver packages to copy from `"$($LocalDriverPackageDirectory.FullName)`" to `"$($DriverPackageDirectory.FullName)`"."
                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                          
                                                            [System.IO.FileInfo]$CopyDriverPackagesLogPath = "$($LogDirectory.FullName)\Robocopy\CopyDriverPackages-ToFinalLocation.log"

                                                            If ([System.IO.Directory]::Exists($CopyDriverPackagesLogPath.Directory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($CopyDriverPackagesLogPath.Directory.FullName)}

                                                            $StartProcessParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                              $StartProcessParameters.FilePath = "$($System32Directory.FullName)\robocopy.exe"
                                                              $StartProcessParameters.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                                $StartProcessParameters.ArgumentList.Add("`"$($LocalDriverPackageDirectory.FullName)`"")
                                                                $StartProcessParameters.ArgumentList.Add("`"$($DriverPackageDirectory.FullName)`"")
                                                                $StartProcessParameters.ArgumentList.Add("/E")
                                                                $StartProcessParameters.ArgumentList.Add("/Z")
                                                                $StartProcessParameters.ArgumentList.Add("/ZB")
                                                                $StartProcessParameters.ArgumentList.Add("/W:5")
                                                                $StartProcessParameters.ArgumentList.Add("/R:3")
                                                                $StartProcessParameters.ArgumentList.Add("/J")
                                                                $StartProcessParameters.ArgumentList.Add("/FP")
                                                                $StartProcessParameters.ArgumentList.Add("/NDL")
                                                                $StartProcessParameters.ArgumentList.Add("/TEE")
                                                                $StartProcessParameters.ArgumentList.Add("/XX")
                                                                $StartProcessParameters.ArgumentList.Add("/MT:16")
                                                                If ($EnableRobocopyIPG) {$StartProcessParameters.ArgumentList.Add("/IPG:125")}
                                                                $StartProcessParameters.ArgumentList.Add("/LOG:`"$($CopyDriverPackagesLogPath.FullName)`"")
                                                              $StartProcessParameters.PassThru = $True
                                                              $StartProcessParameters.Wait = $True
                                                          
                                                          Switch ($ProcessExecutionTable.IsSessionZero)
                                                            {
                                                                {($_ -eq $True)}
                                                                  {
                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Session 0 was detected [User: $($ProcessExecutionTable.ProcessNTAccount)]. The command window will be hidden."
                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                    
                                                                        $StartProcessParameters.WindowStyle = [System.Diagnostics.Processwindowstyle]::Hidden
                                                                  }
                                                          
                                                                Default
                                                                  {
                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Session 0 was not detected [User: $($ProcessExecutionTable.ProcessNTAccount)]. The command window will be shown."
                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                    
                                                                        $StartProcessParameters.WindowStyle = [System.Diagnostics.Processwindowstyle]::Normal
                                                                  }
                                                            }
                                                             
                                                          $CopyDriverPackagesResult = Start-Process @StartProcessParameters

                                                          $AcceptableExitCodeList = @(0, 1, 2, 3, 4, 5, 6, 7, 8)
                                                          
                                                          Switch ($CopyDriverPackagesResult.ExitCode -in $AcceptableExitCodeList)
                                                            {
                                                                {($_ -eq $True)}
                                                                  {
                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The command execution was successful. [Exit Code: $($CopyDriverPackagesResult.ExitCode)]"
                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                  }
                                                          
                                                                {($_ -eq $False)}
                                                                  {
                                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  The command execution was unsuccessful. [Exit Code: $($CopyDriverPackagesResult.ExitCode)]" 
                                                                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                          
                                                                      $ErrorMessage = "$($LoggingDetails.WarningMessage)"
                                                                      $Exception = [System.Exception]::New($ErrorMessage)           
                                                                      $ErrorRecord = [System.Management.Automation.ErrorRecord]::New($Exception, [System.Management.Automation.ErrorCategory]::InvalidResult.ToString(), [System.Management.Automation.ErrorCategory]::InvalidResult, $Process)
                                                          
                                                                      $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                                                                  }
                                                            }
                        
                                                            #Cleanup the local driver package directory (If necessary)
                                                              If ([System.IO.Directory]::Exists($LocalDriverPackageDirectory.FullName) -eq $True)
                                                                {
                                                                    $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove local driver package directory `"$($LocalDriverPackageDirectory.FullName)`". Please Wait..."
                                                                    Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                
                                                                    [String]$DeletionPath = $LocalDriverPackageDirectory.FullName

                                                                    $Null = [Alphaleonis.Win32.Filesystem.Directory]::Delete($DeletionPath, $True, $True)              
                                                                }
                                                        }

                                                      Default
                                                        {
                                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - There are $($LocalDriverPackageCount) windows image driver packages to copy from `"$($LocalDriverPackageDirectory.FullName)`" to `"$($DriverPackageDirectory.FullName)`"."
                                                            Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                        }
                                                  }
                                            }

                                          Default
                                            {
                                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The directory `"$($LocalDriverPackageDirectory.FullName)`" does not exist. The windows image driver packages will not be copied."
                                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                            }
                                      }
                              }
                            Catch
                              {
                                  Throw
                              }
                            Finally
                              {

                              }
                        }
                  }

                #region Export Driver Pack Metadata to XML
                  $XMLWriterSettings = New-Object -TypeName 'System.XML.XMLWriterSettings'
                    $XMLWriterSettings.Indent = $True
                    $XMLWriterSettings.IndentChars = "`t" * 1
                    $XMLWriterSettings.Encoding = [System.Text.Encoding]::Default
                    $XMLWriterSettings.NewLineHandling = [System.XML.NewLineHandling]::None
                    $XMLWriterSettings.ConformanceLevel = [System.XML.ConformanceLevel]::Auto

                  $XMLStringBuilder = New-Object -TypeName 'System.Text.StringBuilder'

                  $XMLWriter = [System.XML.XMLTextWriter]::Create($XMLStringBuilder, $XMLWritersettings)

                  [ScriptBlock]$AddXMLWriterNewLine = {$XMLWriter.WriteWhitespace(("`r`n" * 2))}

                  $XMLWriter.WriteStartDocument()

                  $AddXMLWriterNewLine.Invoke()

                  $XMLWriter.WriteProcessingInstruction("xml-stylesheet", "type='text/xsl' href='style.xsl'")

                  $AddXMLWriterNewLine.Invoke()

                  $DriverPackagePropertyInclusionList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'Enabled'; Expression = {$_.Enabled}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'MinimumOSVersion'; Expression = {$_.OSVersionMinimum}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'MinimumOSVersionAlias'; Expression = {$_.OSReleaseIDMinimum}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'ReleaseID'; Expression = {$_.DriverPackReleaseID}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'ReleaseVersion'; Expression = {$_.DriverPackReleaseVersion}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'ReleaseDate'; Expression = {$_.DriverPackReleaseDate}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'FilePath'; Expression = {$_.FilePath}})
                    $DriverPackagePropertyInclusionList.Add(@{Name = 'MetadataPath'; Expression = {$_.MetadataFilePath}})

                  $XMLWriter.WriteStartElement('Metadata')

                  $XMLWriter.WriteElementString('GeneratedBy', $ProcessExecutionTable.ProcessNTAccount)
                  $XMLWriter.WriteElementString('GeneratedOn', $Env:ComputerName.ToUpper())
                  $XMLWriter.WriteElementString('GeneratedDate', $GetCurrentDateTimeXMLFormat.InvokeReturnAsIs())

                  $XMLWriter.WriteStartElement('ManufacturerList')

                  $ManufacturerGroupList = $DriverPackDownloadList | Group-Object -Property @('Manufacturer') | Sort-Object -Property @('Name')

                  ForEach ($ManufacturerGroup In $ManufacturerGroupList)
                    {                    
                        $ProductNameProperty = 'SystemProductName'
                                
                        Switch ($ManufacturerGroup.Name)
                          {
                              {($_ -iin @('Dell'))}
                                {
                                    [Object]$ProductIDExpression = @{Name = 'ProductID'; Expression = {$_.SystemSKU.ToUpper()}}
                                }

                              {($_ -iin @('HP'))}
                                {
                                    [Object]$ProductIDExpression = @{Name = 'ProductID'; Expression = {[Regex]::Match($_.BaseboardProduct, '^\w{4}').Value.ToUpper()}}
                                }

                              {($_ -iin @('Lenovo'))}
                                {
                                    [Object]$ProductIDExpression = @{Name = 'ProductID'; Expression = {[Regex]::Match($_.SystemProductName, '^\w{4}').Value.ToUpper()}}
                                            
                                    $ProductNameProperty = 'SystemVersion'
                                }

                              Default
                                {
                                    [Object]$ProductIDExpression = @{Name = 'ProductID'; Expression = {$_.BaseboardProduct}}
                                }
                          }
                                
                        $XMLWriter.WriteStartElement('Manufacturer')

                        $XMLWriter.WriteAttributeString('Enabled', $True)
                        $XMLWriter.WriteAttributeString('Name', $ManufacturerGroup.Name)
                        $XMLWriter.WriteAttributeString('EligibilityExpression', ($Script:SettingsTable.ManufacturerList | Where-Object {($_.Name -ieq $ManufacturerGroup.Name)}).EligibilityExpression)
                        $XMLWriter.WriteAttributeString('ProductIDExpression', "@{Name = '$($ProductIDExpression.Name)'; Expression = {$($ProductIDExpression.Expression)}}")

                        $XMLWriter.WriteStartElement('ModelList')

                        $ProductGroupList = $ManufacturerGroup.Group | Select-Object -Property @('*') | Group-Object -Property 'ProductID' | Sort-Object -Property @('Name')

                        ForEach ($ProductGroup In $ProductGroupList)
                          {
                              $XMLWriter.WriteStartElement('Model')

                              $XMLWriter.WriteAttributeString('Enabled', $True)
                              $XMLWriter.WriteAttributeString('Name', $ProductGroup.Group[0].$($ProductNameProperty))

                              $XMLWriter.WriteStartElement('ProductIDList')
                                          
                              ForEach ($ProductID In ($ProductGroup.Group.ProductIDList | Sort-Object -Unique))
                                {
                                    $XMLWriter.WriteElementString('ProductID', $ProductID)
                                }

                              $XMLWriter.WriteEndElement()

                              $XMLWriter.WriteStartElement('OperatingSystemList')

                              $OperatingSystemGroupProperty = 'OSName'

                              $OperatingSystemGroupList = $ProductGroup.Group | Sort-Object -Property {[Regex]::Match($_.OSAlias, '\d+').Value} | Group-Object -Property ($OperatingSystemGroupProperty)

                              ForEach ($OperatingSystemGroup In $OperatingSystemGroupList)
                                {
                                    $XMLWriter.WriteStartElement('OperatingSystem')

                                    $XMLWriter.WriteAttributeString('Enabled', $True)
                                    $XMLWriter.WriteAttributeString('Name', $OperatingSystemGroup.Name)
                                    $XMLWriter.WriteAttributeString('Architecture', $OperatingSystemGroup.Group[0].OSArchitecture)
                                    $XMLWriter.WriteAttributeString('MinimumVersion', ($WindowsReleaseHistory | Where-Object {($_.Name -ieq $OperatingSystemGroup.Name)} | Select-Object -First 1).Version.ToString())

                                    $XMLWriter.WriteStartElement('DriverPackageList')

                                    $DriverPackageList = $OperatingSystemGroupList.Group | Where-Object {($_.$($OperatingSystemGroupProperty) -ieq $OperatingSystemGroup.Name)} | Sort-Object -Property {[Version]$_.MinimumOSVersion} -Descending
                                                
                                    ForEach ($DriverPackage In $DriverPackageList)
                                      {
                                          $DriverPackageEntry = $DriverPackage | Select-Object -Property ($DriverPackagePropertyInclusionList)

                                          $XMLWriter.WriteStartElement('DriverPackage')

                                          ForEach ($DriverPackageProperty In $DriverPackageEntry.PSObject.Properties)
                                              {
                                                  $XMLWriter.WriteAttributeString($DriverPackageProperty.Name, $DriverPackageProperty.Value)
                                              }

                                          $XMLWriter.WriteEndElement()   
                                      }

                                    $XMLWriter.WriteEndElement()

                                    $XMLWriter.WriteEndElement()
                                }

                              $XMLWriter.WriteEndElement()

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

                  [String]$DriverPackageListContents = $XMLStringBuilder.ToString()

                  [System.IO.FileInfo]$DriverPackageListExportPath = "$($DriverPackageDirectory.FullName)\Metadata\DriverPackageList.xml"

                  [Scriptblock]$ExportDriverPackageList = {
                                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to export the driver package list to `"$($DriverPackageListExportPath.FullName)`". Please Wait..."
                                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                              If ([System.IO.Directory]::Exists($DriverPackageListExportPath.Directory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DriverPackageListExportPath.Directory.FullName)}

                                                              $Null = [System.IO.File]::WriteAllText($DriverPackageListExportPath.FullName, $DriverPackageListContents, $XMLWriterSettings.Encoding)
                                                          }

                  Switch ([System.IO.File]::Exists($DriverPackageListExportPath.FullName))
                    {
                        {($_ -eq $True)}
                          {      
                              $MemoryStream = New-Object -TypeName 'System.IO.MemoryStream'
                              $StreamWriter = New-Object -TypeName 'System.IO.StreamWriter' -ArgumentList ($MemoryStream)
                              $Null = $StreamWriter.Write($DriverPackageListContents)
                              $Null = $StreamWriter.Flush()
                              $Null = $MemoryStream.Position = 0

                              $DriverPackageListContentHash = Get-FileHash -InputStream $MemoryStream -Algorithm ($HashAlgorithm)

                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - New driver package list hash: $($DriverPackageListContentHash.Hash)"
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                              $DriverPackageListExportPathHash = Get-FileHash -Path ($DriverPackageListExportPath.FullName) -Algorithm ($HashAlgorithm)

                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Current driver package list hash: $($DriverPackageListExportPathHash.Hash)"
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                              Switch ($DriverPackageListContentHash.Hash -ne $DriverPackageListExportPathHash.Hash)
                                {
                                    {($_ -eq $True)}
                                      {
                                          $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The driver package list `"$($DriverPackageListExportPath.FullName)`" requires an update."
                                          Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                          $Null = $ExportDriverPackageList.InvokeReturnAsIs()
                                      }

                                    Default
                                      {
                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The driver package list `"$($DriverPackageListExportPath.FullName)`" does not require an update."
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                      }
                                }
                          }

                        Default
                        {
                            $Null = $ExportDriverPackageList.InvokeReturnAsIs()
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