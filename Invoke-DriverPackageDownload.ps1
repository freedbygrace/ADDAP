#Requires -Version 3

<#
    .SYNOPSIS
    A brief overview of what your function does
          
    .DESCRIPTION
    Slightly more detailed description of what your function does
          
    .PARAMETER TaskSequenceVariables
    One or more task sequence variable(s) to retrieve during task sequence execution.
    If this parameter is not specified, all task sequence variable(s) will be stored into the variable 'TSVariableTable'.
    Any task sequence variables that are new or have been updated will be saved back to the task sequence engine for futher usage.

    $TSVariable.MyCustomVariableName = "MyCustomVariableValue"
    $TSVariable.Make = "MyDeviceModel"

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
        [ValidateScript({[System.IO.Directory]::Exists($_) -eq $True})]
        [Alias('DPRD')]
        [System.IO.DirectoryInfo]$DriverPackageRootDirectory,
    
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^.+\.(xml)$')]
        [ValidateScript({[System.IO.File]::Exists($_) -eq $True})]
        [Alias('DPMDP')]
        [System.IO.FileInfo]$DriverPackageMetadataPath,

        [Parameter(Mandatory=$False)]
        [Switch]$DisableDownLeveling,

        [Parameter(Mandatory=$False)]
        [Alias('BIMB', 'Buffer', 'BufferInMegabytes')]
        [Int]$SegmentSize = 8192,
        
        [Parameter(Mandatory=$False)]
        [Alias('RD')]
        [Switch]$RandomDelay,

        [Parameter(Mandatory=$False)]
        [Alias('S', 'StageContent', 'StageDriversLocally')]
        [Switch]$Stage,

        [Parameter(Mandatory=$False)]
        [Alias('SRD')]
        [System.IO.DirectoryInfo]$StagingRootDirectory,
    
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('TSVars', 'TSVs')]
        [String[]]$TaskSequenceVariables,
            
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
                                                              Write-Verbose -Message ($LoggingDetails.ErrorMessage) -Verbose
                                                          }

                                                        Switch (($ContinueOnError.IsPresent -eq $False) -or ($ContinueOnError -eq $False))
                                                          {
                                                              {($_ -eq $True)}
                                                                {                  
                                                                    Throw
                                                                }
                                                          }
                                                    }
	
        #Log task sequence variables if debug mode is enabled within the task sequence
          Try
            {
                [System.__ComObject]$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment"
              
                If ($Null -ine $TSEnvironment)
                  {
                      $IsRunningTaskSequence = $True
                      
                      [Boolean]$IsConfigurationManagerTaskSequence = [String]::IsNullOrEmpty($TSEnvironment.Value("_SMSTSPackageID")) -eq $False
                      
                      Switch ($IsConfigurationManagerTaskSequence)
                        {
                            {($_ -eq $True)}
                              {
                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A Microsoft Endpoint Configuration Manager (MECM) task sequence was detected."
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                              }
                                      
                            {($_ -eq $False)}
                              {
                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A Microsoft Deployment Toolkit (MDT) task sequence was detected."
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                              }
                        }
                  }
            }
          Catch
            {
                $IsRunningTaskSequence = $False
            }
            
        #Determine default parameter value(s)       
          Switch ($True)
            {
                {([String]::IsNullOrEmpty($LogDirectory) -eq $True) -or ([String]::IsNullOrWhiteSpace($LogDirectory) -eq $True)}
                  {
                      Switch ($IsRunningTaskSequence)
                        {
                            {($_ -eq $True)}
                              {
                                  Switch ($IsConfigurationManagerTaskSequence)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [String]$_SMSTSLogPath = "$($TSEnvironment.Value('_SMSTSLogPath'))"
                                          }
                              
                                        {($_ -eq $False)}
                                          {
                                              [String]$_SMSTSLogPath = "$($TSEnvironment.Value('LogPath'))"
                                          }
                                    }

                                  Switch ([String]::IsNullOrEmpty($_SMSTSLogPath))
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [System.IO.DirectoryInfo]$TSLogDirectory = "$($Env:Windir)\Temp\SMSTSLog"    
                                          }
                                    
                                        {($_ -eq $False)}
                                          {
                                              Switch ($True)
                                                {
                                                    {(Test-Path -Path ($_SMSTSLogPath) -PathType Container)}
                                                      {
                                                          [System.IO.DirectoryInfo]$TSLogDirectory = ($_SMSTSLogPath)
                                                      }
                                    
                                                    {(Test-Path -Path ($_SMSTSLogPath) -PathType Leaf)}
                                                      {
                                                          [System.IO.DirectoryInfo]$TSLogDirectory = Split-Path -Path ($_SMSTSLogPath) -Parent
                                                      }
                                                }    
                                          }
                                    }
                                         
                                  [System.IO.DirectoryInfo]$LogDirectory = "$($TSLogDirectory.FullName)\$($ScriptPath.BaseName)"
                              }
                  
                            {($_ -eq $False)}
                              {
                                  Switch ($IsWindowsPE)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [System.IO.FileInfo]$MDTBootImageDetectionPath = "$($Env:SystemDrive)\Deploy\Scripts\Litetouch.wsf"
                                      
                                              [Boolean]$MDTBootImageDetected = Test-Path -Path ($MDTBootImageDetectionPath.FullName)
                                              
                                              Switch ($MDTBootImageDetected)
                                                {
                                                    {($_ -eq $True)}
                                                      {
                                                          [System.IO.DirectoryInfo]$LogDirectory = "$($Env:SystemDrive)\MININT\SMSOSD\OSDLOGS\$($ScriptPath.BaseName)"
                                                      }
                                          
                                                    {($_ -eq $False)}
                                                      {
                                                          [System.IO.DirectoryInfo]$LogDirectory = "$($Env:Windir)\Temp\SMSTSLog"
                                                      }
                                                }
                                          }
                                          
                                        {($_ -eq $False)}
                                          {
                                              [System.IO.DirectoryInfo]$ApplicationDataRootDirectory = "$($Env:ProgramData)\Invoke-DriverPackageCreator"

                                              [System.IO.DirectoryInfo]$LogDirectory = "$($ApplicationDataRootDirectory.FullName)\Logs"
                                          }
                                    }   
                              }
                        }
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
                      Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
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
                      Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                      
                      For ($SortedLogListIndex = 0; $SortedLogListIndex -lt $SortedLogList.Count; $SortedLogListIndex++)
                        {
                            Try
                              {
                                  $Log = $SortedLogList[$SortedLogListIndex]

                                  $LogAge = New-TimeSpan -Start ($Log.LastWriteTime) -End (Get-Date)

                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to cleanup log file `"$($Log.FullName)`". Please Wait... [Last Modified: $($Log.LastWriteTime.ToString($DateTimeMessageFormat))] [Age: $($LogAge.Days.ToString()) day(s); $($LogAge.Hours.ToString()) hours(s); $($LogAge.Minutes.ToString()) minute(s); $($LogAge.Seconds.ToString()) second(s)]."
                                  Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                  
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
                #If necessary, create, get, and or set any task sequence variable(s).   
                  Switch ($IsRunningTaskSequence)
                    {
                        {($_ -eq $True)}
                          {
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A task sequence is currently running."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                              
                              $TaskSequenceVariableRetrievalList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                
                              Switch ($TaskSequenceVariables.Count -gt 0)
                                {
                                    {($_ -eq $True)}
                                      {
                                          ForEach ($TaskSequenceVariable In $TaskSequenceVariables)
                                            {
                                                $TaskSequenceVariableRetrievalList.Add($TaskSequenceVariable)
                                            }
                                      }
                                }
  
                              $TSVariableTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                    
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to retrieve the task sequence variable list. Please Wait..."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                      
                              Switch ($TaskSequenceVariableRetrievalList.Count -gt 0)
                                {
                                    {($_ -eq $True)}
                                      {
                                          $TSVariableList = $TSEnvironment.GetVariables() | Where-Object {($_ -iin $TaskSequenceVariableRetrievalList)} | Sort-Object
                                      }
                                      
                                    Default
                                      {
                                          $TSVariableList = $TSEnvironment.GetVariables() | Sort-Object
                                      }
                                }
                      
                              ForEach ($TSVariable In $TSVariableList)
                                {
                                    $TSVariableName = $TSVariable
                                    $TSVariableValue = $TSEnvironment.Value($TSVariableName)
                      
                                    Switch ($True)
                                      {
                                          {($TSVariableName -inotmatch '(^_SMSTSTaskSequence$)|(^TaskSequence$)|(^.*Pass.*word.*$)')}
                                            {
                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to retrieve the value of task sequence variable `"$($TSVariableName)`". Please Wait..."
                                                Write-Verbose -Message ($LoggingDetails.LogMessage)
                                            }
                                                                            
                                          {($TSVariableTable.Contains($TSVariableName) -eq $False)}
                                            {
                                                $TSVariableTable.Add($TSVariableName, $TSVariableValue)    
                                            }             
                                      } 
                                }
                          }
                    }

                #Set default parameter value(s)
                  Switch ($IsRunningTaskSequence)
                    {
                        {($_ -eq $True)}
                          {
                              Switch ($True)
                                {
                                    {([String]::IsNullOrEmpty($DriverPackageRootDirectory) -eq $True) -or ([String]::IsNullOrWhiteSpace($DriverPackageRootDirectory) -eq $True)}
                                      {
                                          [System.IO.DirectoryInfo]$DriverPackageRootDirectory = "$($TSVariableTable.DEPLOYROOT)\Out-Of-Box-Driver-Packages"
                                      }

                                    {([String]::IsNullOrEmpty($DriverPackageMetadataPath) -eq $True) -or ([String]::IsNullOrWhiteSpace($DriverPackageMetadataPath) -eq $True)}
                                      {
                                          [System.IO.FileInfo]$DriverPackageMetadataPath = "$($DriverPackageRootDirectory.FullName)\Metadata\DriverPackageList.xml"
                                      }
                                }
                          }

                        Default
                          {
                              Switch ($True)
                                {
                                    {([String]::IsNullOrEmpty($DriverPackageRootDirectory) -eq $True) -or ([String]::IsNullOrWhiteSpace($DriverPackageRootDirectory) -eq $True)}
                                      {
                                          [System.IO.DirectoryInfo]$DriverPackageRootDirectory = "C:\ProgramData\Invoke-DriverPackageCreator\DriverPackages"
                                      }

                                    {([String]::IsNullOrEmpty($DriverPackageMetadataPath) -eq $True) -or ([String]::IsNullOrWhiteSpace($DriverPackageMetadataPath) -eq $True)}
                                      {
                                          [System.IO.FileInfo]$DriverPackageMetadataPath = "$($DriverPackageRootDirectory.FullName)\Metadata\DriverPackageList.xml"
                                      }
                                }
                          }
                    }

                #Determine which driver package(s) are applicable to the deployed operating system and product ID
                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A task sequence is currently running."
                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                  $DriverPackageDownloadList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to read the contents of `"$($DriverPackageMetadataPath.FullName)`". Please Wait..."
                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                  
                  $DriverPackageMetadataContents = [System.IO.File]::ReadAllText($DriverPackageMetadataPath.FullName)

                  $DriverPackageXMLDocument = New-Object -TypeName 'System.Xml.XmlDocument'
                    $DriverPackageXMLDocument.LoadXml($DriverPackageMetadataContents)

                  $DriverPackageMetadata = $DriverPackageXMLDocument.Metadata

                  $ManufacturerList = $DriverPackageMetadata.ManufacturerList.Manufacturer

                  $ManufacturerDetails = $ManufacturerList | Where-Object {($_.Enabled -eq $True) -and ($MSSystemInformation.SystemManufacturer -imatch $_.EligibilityExpression)}

                  $ManufacturerDetailsCount = ($ManufacturerDetails | Measure-Object).Count

                  Switch ($ManufacturerDetailsCount -gt 0)
                    {
                        {($_ -eq $True)}
                          {
                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The current system manufacturer of `"$($MSSystemInformation.SystemManufacturer)`" matches the manufacturer list for `"$($ManufacturerDetails.Name)`" [Eligibility Expression: $($ManufacturerDetails.EligibilityExpression)]."
                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                            
                              $ProductIDExpression = [Scriptblock]::Create($ManufacturerDetails.ProductIDExpression)

                              $ProductID = ($MSSystemInformation | Select-Object -Property ($ProductIDExpression.Invoke())).ProductID

                              $ModelList = $ManufacturerDetails.ModelList.Model

                              $ModelDetails = $ModelList | Where-Object {($_.Enabled -eq $True) -and ($_.ProductIDList.ProductID -icontains $ProductID)}

                              $ModelDetailsCount = ($ModelDetails | Measure-Object).Count

                              Switch ($ModelDetailsCount -gt 0)
                                {
                                    {($_ -eq $True)}
                                      {        
                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($ModelDetailsCount) model(s) contain the product ID of `"$($ProductID)`"."
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                          ForEach ($Model In $ModelDetails)
                                            {
                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The current product ID of `"$($ProductID)`" is contained within the product ID list for the `"$($Model.Name)`" device model."
                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Product ID List: $($Model.ProductIDList.ProductID -Join ', ')]"
                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                            }
                                            
                                          $OperatingSystemPropertyList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                            $OperatingSystemPropertyList.Add(@{Name = 'MinimumVersion'; Expression = {[Version]$_.MinimumVersion}})
                                            $OperatingSystemPropertyList.Add('*')
                                          
                                          $OperatingSystemList = $ModelDetails.OperatingSystemList.OperatingSystem | Select-Object -Property ($OperatingSystemPropertyList) -ExcludeProperty @('MinimumVersion')

                                          $InvokeRegistryHiveActionParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

                                          $FixedVolumeList = [System.IO.DriveInfo]::GetDrives() | Where-Object {($_.DriveType -iin @('Fixed')) -and ($_.IsReady -eq $True) -and ($_.Name.TrimEnd('\') -inotin @($Env:SystemDrive)) -and (([String]::IsNullOrEmpty($_.Name) -eq $False) -or ([String]::IsNullOrWhiteSpace($_.Name) -eq $False))} | Sort-Object -Property @('TotalSize')

                                          :FixedVolumeLoop ForEach ($FixedVolume In $FixedVolumeList)
                                              {
                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to check fixed volume `"$($FixedVolume.Name.TrimEnd('\'))`" for a valid installation of Windows."
                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                  
                                                  [System.IO.DirectoryInfo]$WindowsDirectory = "$($FixedVolume.Name.TrimEnd('\'))\Windows"
                                          
                                                  Switch ([System.IO.Directory]::Exists($WindowsDirectory.FullName))
                                                      {
                                                          {($_ -eq $True)}
                                                              {
                                                                  $WindowsDirectoryItemList = Get-ChildItem -Path ($WindowsDirectory.FullName) -ErrorAction SilentlyContinue
                                          
                                                                  $WindowsDirectoryItemListCount = ($WindowsDirectoryItemList | Measure-Object).Count
                                          
                                                                  Switch (($WindowsDirectoryItemListCount -ge 2) -and ($WindowsDirectoryItemList | Where-Object {($_.Name -ieq 'explorer.exe')}))
                                                                      {
                                                                          {($_ -eq $True)}
                                                                              {
                                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Fixed volume `"$($FixedVolume.Name.TrimEnd('\'))`" contains a valid installation of Windows."
                                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                                  $WindowsImageDriveInfo = New-Object -TypeName 'System.IO.DriveInfo' -ArgumentList "$($FixedVolume.Name.TrimEnd('\'))"

                                                                                  $InvokeRegistryHiveActionParameters.HivePath = "$($WindowsImageDriveInfo.Name.TrimEnd('\').Toupper())\Windows\System32\Config\SOFTWARE"
                                                                                  
                                                                                  Break FixedVolumeLoop
                                                                              }
                                                                      }       
                                                              }
                                                      }    
                                              }

                                          #$SecondLargestVolume = ($FixedVolumeList | Sort-Object -Property 'TotalSize' -Descending)[1]

                                          #[System.IO.DirectoryInfo]$DriverPackageDownloadDirectory = "$($SecondLargestVolume.Name.TrimEnd('\'))\Downloads"
                                          
                                          [System.IO.DirectoryInfo]$DriverPackageDownloadDirectory = "$($WindowsImageDriveInfo.Name.TrimEnd('\').Toupper())\Downloads"
  
                                          $InvokeRegistryHiveActionParameters.KeyPath = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                            $InvokeRegistryHiveActionParameters.KeyPath.Add('Root\Microsoft\Windows NT\CurrentVersion')
                                          $InvokeRegistryHiveActionParameters.ValueNameExpression = New-Object -TypeName 'System.Collections.Generic.List[Regex]'
                                            $InvokeRegistryHiveActionParameters.ValueNameExpression.Add('.*')
                                          $InvokeRegistryHiveActionParameters.ContinueOnError = $False
                                          $InvokeRegistryHiveActionParameters.Verbose = $True
                                      
                                          $InvokeRegistryHiveActionResult = Invoke-RegistryHiveAction @InvokeRegistryHiveActionParameters

                                          $WindowsImageDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                            $WindowsImageDetails.MajorVersionNumber = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'CurrentMajorVersionNumber')}).Value
                                            $WindowsImageDetails.MinorVersionNumber = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'CurrentMinorVersionNumber')}).Value
                                            $WindowsImageDetails.BuildNumber = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'CurrentBuildNumber')}).Value
                                            $WindowsImageDetails.RevisionNumber = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'UBR')}).Value
                                            $WindowsImageDetails.Version = New-Object -TypeName 'System.Version' -ArgumentList @($WindowsImageDetails.MajorVersionNumber, $WindowsImageDetails.MinorVersionNumber, $WindowsImageDetails.BuildNumber, $WindowsImageDetails.RevisionNumber)
                                            $WindowsImageDetails.ReleaseNumber = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'ReleaseID')}).Value
                                            $WindowsImageDetails.ReleaseID = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'DisplayVersion')}).Value
                                            $WindowsImageDetails.BuildLabEX = ($InvokeRegistryHiveActionResult[0].ValueList | Where-Object {($_.Name -ieq 'BuildLabEX')}).Value

                                          ForEach ($WindowsImageDetail In $WindowsImageDetails.GetEnumerator())
                                              {
                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Deployed Operating System - $($WindowsImageDetail.Key): $($WindowsImageDetail.Value)"
                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                              }

                                          $OperatingSystemCriteria = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                            
                                          Switch ($WindowsImageDetails.BuildLabEX)
                                            {
                                                {($_ -imatch '.*amd64.*')}
                                                  {
                                                      $OperatingSystemCriteria.Architecture = 'X64'
                                                  }

                                                Default
                                                  {
                                                      $OperatingSystemCriteria.Architecture = 'X86'
                                                  }
                                            }

                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Deployed Operating System - Architecture: $($OperatingSystemCriteria.Architecture)"
                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                          $OperatingSystemCriteria.Version = $WindowsImageDetails.Version

                                          $OperatingSystemDetails = $OperatingSystemList | Where-Object {($_.Enabled -eq $True) -and ($_.Architecture -ieq $OperatingSystemCriteria.Architecture) -and (($OperatingSystemCriteria.Version.Major -eq $_.MinimumVersion.Major) -and ($OperatingSystemCriteria.Version.Minor -eq $_.MinimumVersion.Minor))}

                                          $OperatingSystemDetailsCount = ($OperatingSystemDetails | Measure-Object).Count
                                          
                                          Switch ($OperatingSystemDetailsCount -gt 0)
                                            {
                                                {($_ -eq $True)}
                                                  {
                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The deployed operating system image kernel version of $($WindowsImageDetails.MajorVersionNumber).$($WindowsImageDetails.MinorVersionNumber) matches $($OperatingSystemDetails.Count) supported operating system(s)."
                                                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                      For ($OperatingSystemDetailIndex = 0; $OperatingSystemDetailIndex -lt $OperatingSystemDetailsCount; $OperatingSystemDetailIndex++)
                                                        {
                                                            $OperatingSystemDetailNumber = $OperatingSystemDetailIndex + 1
                                                          
                                                            $OperatingSystemDetail = $OperatingSystemDetails[$OperatingSystemDetailIndex]
                                                            
                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supported Operating System #$($OperatingSystemDetailNumber.ToString('00')) - $($OperatingSystemDetail.Name) - [Minimum Version: $($OperatingSystemDetail.MinimumVersion)]"
                                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                        }
                                                    
                                                      $DriverPackagePropertyList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                                        $DriverPackagePropertyList.Add(@{Name = 'MinimumOSVersion'; Expression = {[Version]$_.MinimumOSVersion}})
                                                        $DriverPackagePropertyList.Add('*')
                                                    
                                                      $DriverPackages = $OperatingSystemDetails.DriverPackageList.DriverPackage | Select-Object -Property ($DriverPackagePropertyList) -ExcludeProperty @('MinimumOSVersion')

                                                      Switch ($DisableDownLeveling.IsPresent)
                                                        {
                                                            {($_ -eq $True)}
                                                              {
                                                                  $DriverPackageList = $DriverPackages | Where-Object {($_.Enabled -eq $True) -and (($OperatingSystemCriteria.Version.Major -eq $_.MinimumOSVersion.Major) -and ($OperatingSystemCriteria.Version.Minor -eq $_.MinimumOSVersion.Minor) -and ($_.MinimumOSVersion.Build -eq $OperatingSystemCriteria.Version.Build))}
                                                              }

                                                            Default
                                                              {
                                                                  $DriverPackageList = $DriverPackages | Where-Object {($_.Enabled -eq $True) -and (($OperatingSystemCriteria.Version.Major -eq $_.MinimumOSVersion.Major) -and ($OperatingSystemCriteria.Version.Minor -eq $_.MinimumOSVersion.Minor) -and ($_.MinimumOSVersion.Build -le $OperatingSystemCriteria.Version.Build))}
                                                              }
                                                        }

                                                      $DriverPackageListCount = ($DriverPackageList | Measure-Object).Count

                                                      Switch ($DriverPackageListCount -gt 0)
                                                        {
                                                            {($_ -eq $True)}
                                                              {                 
                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackageListCount) driver package(s) were found."
                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                  For ($DriverPackageListIndex = 0; $DriverPackageListIndex -lt $DriverPackageListCount; $DriverPackageListIndex++)
                                                                    {
                                                                        $DriverPackageListItemNumber = $DriverPackageListIndex + 1
                                                                      
                                                                        $DriverPackageListItem = $DriverPackageList[$DriverPackageListIndex]
                                                                        
                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Driver Package #$($DriverPackageListItemNumber.ToString('00')) - $(Split-Path -Path $DriverPackageListItem.FilePath -Leaf) [Minimum Operating System Version: $($DriverPackageListItem.MinimumOSVersion)] [Release Date: $($DriverPackageListItem.ReleaseDate)]"
                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                    }

                                                                  $DriverPackage = $DriverPackageList | Sort-Object -Property {[DateTime]$_.ReleaseDate} -Descending | Select-Object -First 1

                                                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Selected the most recent driver package of `"$(Split-Path -Path $DriverPackage.FilePath -Leaf)`" [Release Date: $($DriverPackage.ReleaseDate)]."
                                                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                  $DriverPackageDownloadProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                    $DriverPackageDownloadProperties.PackagePath = "$($DriverPackageRootDirectory.FullName)\$($DriverPackage.FilePath)" -As [System.IO.FileInfo]
                                                                    $DriverPackageDownloadProperties.MetadataPath = "$($DriverPackageRootDirectory.FullName)\$($DriverPackage.MetadataPath)" -As [System.IO.FileInfo]
                                                                    $DriverPackageDownloadProperties.DownloadPath = "$($DriverPackageDownloadDirectory.FullName)\DriverPackages\$($DriverPackageDownloadProperties.PackagePath.Name)" -As [System.IO.FileInfo]
                                                                    $DriverPackageDownloadProperties.Details = $Null

                                                                  Switch ([System.IO.File]::Exists($DriverPackageDownloadProperties.PackagePath.FullName))
                                                                    {
                                                                        {($_ -eq $True)}
                                                                          {
                                                                              Switch ([System.IO.File]::Exists($DriverPackageDownloadProperties.MetadataPath.FullName))
                                                                                {
                                                                                    {($_ -eq $True)}
                                                                                      {
                                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add driver package `"$($DriverPackageDownloadProperties.PackagePath.FullName)`" to the download list. Please Wait..."
                                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                                        
                                                                                          $DriverPackageDownloadProperties.Details = ConvertFrom-JSON -InputObject ([System.IO.File]::ReadAllText($DriverPackageDownloadProperties.MetadataPath.FullName))

                                                                                          $DriverPackageDownloadObject = New-Object -TypeName 'PSObject' -Property ($DriverPackageDownloadProperties)

                                                                                          $DriverPackageDownloadList.Add($DriverPackageDownloadObject)
                                                                                      }

                                                                                    Default
                                                                                      {
                                                                                          $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The driver package metadata file `"$($DriverPackageProperties.MetadataPath.FullName)`" does not exist."
                                                                                          Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                      }
                                                                                }
                                                                          }

                                                                        Default
                                                                          {
                                                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The driver package file `"$($DriverPackageProperties.PackagePath.FullName)`" does not exist."
                                                                              Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                          }
                                                                    }    
                                                              }

                                                            Default
                                                              {
                                                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackageListCount) driver package(s) were found."
                                                                  Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                              }
                                                        }
                                                  }

                                                Default
                                                  {                                                    
                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($OperatingSystemDetails.Count) operating system(s) matching version `"$($OperatingSystemCriteria.Version.Major).$($OperatingSystemCriteria.Version.Minor)`" [Architecture: $($OperatingSystemCriteria.Architecture)] were found."
                                                      Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                  }
                                            }
                                      }

                                    Default
                                      {
                                          $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($ModelDetailsCount) model(s) containing product ID `"$($ProductID)`" in their product ID list could be found."
                                          Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                      }
                                }    
                          }

                        Default
                          {
                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($ManufacturerDetailsCount) manufacturers whose eligibility expression matches `"$($MSSystemInformation.SystemManufacturer)`" could be found."
                              Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                          }
                    }
                                                            
                #Process generic driver package(s)
                    [System.IO.DirectoryInfo]$GenericDriverPackageRootDirectory = "$($DriverPackageRootDirectory.FullName)\Generic"

                    Switch ([System.IO.Directory]::Exists($GenericDriverPackageRootDirectory.FullName))
                      {
                          {($_ -eq $True)}
                            {
                                $GenericDriverPackageMetadataFileList = Get-ChildItem -Path ($GenericDriverPackageRootDirectory.FullName) -Filter '*.json' -Recurse -Force | Where-Object {($_ -is [System.IO.FileInfo])}

                                ForEach ($GenericDriverPackageMetadataFile In $GenericDriverPackageMetadataFileList)
                                  {
                                      $GenericDriverPackageMetadataFileContents = [System.IO.File]::ReadAllText($GenericDriverPackageMetadataFile.FullName, [System.Text.Encoding]::Default)

                                      $GenericDriverPackageDetails = Try {ConvertFrom-JSON -InputObject ($GenericDriverPackageMetadataFileContents)} Catch
                                        {
                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package metadata file `"$($GenericDriverPackageMetadataFile.FullName)`" contains invalid JSON. Skipping..."
                                            Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                            
                                            Continue
                                        }

                                      Switch ($GenericDriverPackageDetails.Enabled)
                                        {
                                            {($_ -eq $True)}
                                              {                                                
                                                  Switch ((($MSSystemInformation.BaseBoardManufacturer -imatch $GenericDriverPackageDetails.Metadata.ManufacturerInclusionExpression) -or ($MSSystemInformation.SystemManufacturer -imatch $GenericDriverPackageDetails.Metadata.ManufacturerInclusionExpression)) -and (($MSSystemInformation.BaseBoardManufacturer -inotmatch $GenericDriverPackageDetails.Metadata.ManufacturerExclusionExpression) -or ($MSSystemInformation.SystemManufacturer -inotmatch $GenericDriverPackageDetails.Metadata.ManufacturerExclusionExpression)))
                                                    {
                                                        {($_ -eq $True)}
                                                          {
                                                              Switch ((($MSSystemInformation.BaseBoardProduct -imatch $GenericDriverPackageDetails.Metadata.ProductIDInclusionExpression) -or ($MSSystemInformation.SystemProductName -imatch $GenericDriverPackageDetails.Metadata.ProductIDInclusionExpression) -or ($MSSystemInformation.SystemSKU -imatch $GenericDriverPackageDetails.Metadata.ProductIDInclusionExpression) -or ($MSSystemInformation.SystemVersion -imatch $GenericDriverPackageDetails.Metadata.ProductIDInclusionExpression)) -and (($MSSystemInformation.BaseBoardProduct -inotmatch $GenericDriverPackageDetails.Metadata.ProductIDExclusionExpression) -and ($MSSystemInformation.SystemProductName -inotmatch $GenericDriverPackageDetails.Metadata.ProductIDExclusionExpression) -and ($MSSystemInformation.SystemSKU -inotmatch $GenericDriverPackageDetails.Metadata.ProductIDExclusionExpression) -and ($MSSystemInformation.SystemVersion -inotmatch $GenericDriverPackageDetails.Metadata.ProductIDExclusionExpression)))
                                                                {
                                                                    {($_ -eq $True)}
                                                                      {
                                                                          $GenericDriverPackageOSVersion = $GenericDriverPackageDetails.Metadata.OSVersionMinimum -As [System.Version]
                                                  
                                                                          Switch (($GenericDriverPackageOSVersion.Major -eq $OperatingSystemCriteria.Version.Major) -and ($GenericDriverPackageOSVersion.Minor -eq $OperatingSystemCriteria.Version.Minor) -and ($GenericDriverPackageOSVersion.Build -le $OperatingSystemCriteria.Version.Build))
                                                                            {
                                                                                {($_ -eq $True)}
                                                                                  {
                                                                                      Switch ($OperatingSystemCriteria.Architecture -imatch $GenericDriverPackageDetails.Metadata.OSArchitectureExpression)
                                                                                        {
                                                                                            {($_ -eq $True)}
                                                                                              {
                                                                                                  $GenericDriverPackageDownloadProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                                                    $GenericDriverPackageDownloadProperties.PackagePath = "$($GenericDriverPackageRootDirectory.FullName)\$($GenericDriverPackageDetails.Metadata.FilePath)" -As [System.IO.FileInfo]
                                                                                                    $GenericDriverPackageDownloadProperties.MetadataPath = "$($GenericDriverPackageRootDirectory.FullName)\$($GenericDriverPackageDetails.Metadata.MetadataPath)" -As [System.IO.FileInfo]
                                                                                                    $GenericDriverPackageDownloadProperties.DownloadPath = "$($DriverPackageDownloadDirectory.FullName)\DriverPackages\$($GenericDriverPackageDownloadProperties.PackagePath.Name)" -As [System.IO.FileInfo]
                                                                                                    $GenericDriverPackageDownloadProperties.Details = $Null

                                                                                                  Switch ([System.IO.File]::Exists($GenericDriverPackageDownloadProperties.PackagePath.FullName))
                                                                                                    {
                                                                                                        {($_ -eq $True)}
                                                                                                          {
                                                                                                              Switch ([System.IO.File]::Exists($GenericDriverPackageDownloadProperties.MetadataPath.FullName))
                                                                                                                {
                                                                                                                    {($_ -eq $True)}
                                                                                                                      {
                                                                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add generic driver package `"$($GenericDriverPackageDownloadProperties.PackagePath.FullName)`" to the download list. Please Wait..."
                                                                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                                                                        
                                                                                                                          $GenericDriverPackageDownloadProperties.Details = ConvertFrom-JSON -InputObject ([System.IO.File]::ReadAllText($GenericDriverPackageDownloadProperties.MetadataPath.FullName))

                                                                                                                          $GenericDriverPackageDownloadObject = New-Object -TypeName 'PSObject' -Property ($GenericDriverPackageDownloadProperties)

                                                                                                                          $DriverPackageDownloadList.Add($GenericDriverPackageDownloadObject)
                                                                                                                      }

                                                                                                                    Default
                                                                                                                      {
                                                                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the generic driver package metadata file `"$($GenericDriverPackageProperties.MetadataPath.FullName)`" does not exist."
                                                                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                                                                                      }
                                                                                                                }
                                                                                                          }

                                                                                                        Default
                                                                                                          {
                                                                                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the driver package file `"$($GenericDriverPackageProperties.PackagePath.FullName)`" does not exist."
                                                                                                              Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                                          }
                                                                                                    }
                                                                                              }

                                                                                              Default
                                                                                              {
                                                                                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the deployed operating system architecture of `"$($OperatingSystemCriteria.Architecture)`" does not match the oeprating system expression of `"$($GenericDriverPackageDetails.OSArchitectureExpression)`". Skipping..."
                                                                                                  Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                              }
                                                                                        }
                                                                                  }

                                                                                  Default
                                                                                  {
                                                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the minimum required operating system version of `"$($GenericDriverPackageOSVersion.ToString())`" is not less than or equal to the deployed operating system version of `"$($OperatingSystemCriteria.Version.ToString())`". Skipping..."
                                                                                      Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                  }
                                                                            }
                                                                      }

                                                                      Default
                                                                      {
                                                                          $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the device product ID either does not match `"$($GenericDriverPackageDetails.Metadata.ProductIDInclusionExpression)`" or matches `"$($GenericDriverPackageDetails.Metadata.ProductIDExclusionExpression)`". Skipping..."
                                                                          Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                      }
                                                                }
                                                          }

                                                          Default
                                                          {
                                                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because the device manufacturer either does not match `"$($GenericDriverPackageDetails.Metadata.ManufacturerInclusionExpression)`" or matches `"$($GenericDriverPackageDetails.Metadata.ManufacturerExclusionExpression)`". Skipping..."
                                                              Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                                          }
                                                    }        
                                              }

                                            Default
                                              {
                                                  $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The generic driver package of `"$($GenericDriverPackageDetails.Metadata.Name)`" is excluded because it has been disabled. Skipping..."
                                                  Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                              }
                                        }
                                  }
                            }
                      }

                #Download driver packages
                    Switch ($True)
                      {
                          {($IsRunningTaskSequence -eq $True) -and ($IsConfigurationManagerTaskSequence -eq $True)}
                            {
                                #Use an alternative way of downloading the driver package content
                            }

                          Default
                            {                      
                                Switch ($DriverPackageDownloadList.Count -gt 0)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackageDownloadList.Count) driver package(s) need to be downloaded."
                                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                            $DriverPackagesToApply = New-Object -TypeName 'System.Collections.Generic.List[System.IO.FileInfo]'

                                            ForEach ($DriverPackageDownload In $DriverPackageDownloadList)
                                              {
                                                    $CopyItemWithProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                      $CopyItemWithProgressParameters.Path = $DriverPackageDownload.PackagePath.FullName
                                                      $CopyItemWithProgressParameters.Destination = $DriverPackageDownload.DownloadPath.Directory.FullName
                                                      $CopyItemWithProgressParameters.Force = $True
                                                      $CopyItemWithProgressParameters.SegmentSize = $SegmentSize
                                                      $CopyItemWithProgressParameters.RandomDelay = $RandomDelay.IsPresent
                                                      $CopyItemWithProgressParameters.ContinueOnError = $False
                                                      $CopyItemWithProgressParameters.Verbose = $True

                                                    $CopyItemWithProgressResult = Copy-ItemWithProgress @CopyItemWithProgressParameters
                                                    
                                                    $DriverPackagesToApply.Add($CopyItemWithProgressResult.Destination)
                                              }        
                                        }

                                      Default
                                        {
                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackageDownloadList.Count) driver package(s) need to be downloaded."
                                            Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                                        }
                                  }       
                            }
                      }

              #Apply the downloaded driver packages to the Windows installation
                Switch ($DriverPackagesToApply.Count -gt 0)
                  {
                      {($_ -eq $True)}
                        {
                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackagesToApply.Count) driver package(s) need to be applied to the Windows installation contained on volume `"$($WindowsImageDriveInfo.Name.TrimEnd('\').Toupper())`"."
                            Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                            [System.IO.DirectoryInfo]$WindowsImageMountRootDirectory = "$($WindowsImageDriveInfo.Name.TrimEnd('\'))\WIMMount"

                            [System.IO.DirectoryInfo]$DISMLogDirectory = "$($LogDirectory.FullName)\DISM"

                            If ([System.IO.Directory]::Exists($DISMLogDirectory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DISMLogDirectory.FullName)}

                            $FileSystemObject = New-Object -ComObject 'Scripting.FileSystemObject'

                            For ($DriverPackagesToApplyIndex = 0; $DriverPackagesToApplyIndex -lt $DriverPackagesToApply.Count; $DriverPackagesToApplyIndex++)
                              {           
                                  $DriverPackageToApply = $DriverPackagesToApply[$DriverPackagesToApplyIndex]

                                  $DriverPackageToApplyNumber = $DriverPackagesToApplyIndex + 1

                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process driver pack image #$($DriverPackageToApplyNumber.ToString('00')) - $($DriverPackageToApply.FullName)"
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                  $DriverPackageImageList = Get-WindowsImage -ImagePath "$($DriverPackageToApply.FullName)"
    
                                  ForEach ($DriverPackageImage In $DriverPackageImageList)
                                    {
                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to process driver pack image index $($DriverPackageImage.ImageIndex). Please Wait..."
                                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                      
                                        $DISMCommandProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                          $DISMCommandProperties.MountDirectory = "$($WindowsImageMountRootDirectory.FullName)\Image$($DriverPackageToApplyNumber.ToString('00'))\Index$($DriverPackageImage.ImageIndex.ToString('00'))" -As [System.IO.DirectoryInfo]
                                          $DISMCommandProperties.LogLevel = 3
                                      
                                        $DISMCommandList = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                          $DISMCommandList.MountImage = "/Mount-Image /ImageFile:`"$($DriverPackageImage.ImagePath)`" /Index:$($DriverPackageImage.ImageIndex) /MountDir:`"$($DISMCommandProperties.MountDirectory.FullName)`" /ReadOnly"
                                          $DISMCommandList.AddDrivers = "/Image:$($WindowsImageDriveInfo.Name.TrimEnd('\')) /Add-Driver /Driver:`"$($DISMCommandProperties.MountDirectory.FullName)`" /Recurse"
                                          $DISMCommandList.UnmountImage = "/Unmount-Image /MountDir:`"$($DISMCommandProperties.MountDirectory.FullName)`" /Discard"

                                        If ([System.IO.Directory]::Exists($DISMCommandProperties.MountDirectory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DISMCommandProperties.MountDirectory.FullName)}

                                        $DISMCommandCounter = 1
                                        
                                        ForEach ($DISMCommand In $DISMCommandList.GetEnumerator())
                                          {
                                              $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to execute the command(s) associated with the `"$($DISMCommand.Key)`" key. Please Wait..."
                                              Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                              $StartDISMCommandProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                $StartDISMCommandProgressParameters.Activity = "Attempting to `"$($DISMCommand.Key)`" from index $($DriverPackageImage.ImageIndex) within $($FileSystemObject.GetFile($DriverPackageImage.ImagePath).ShortName). Please Wait..."
                                                $StartDISMCommandProgressParameters.Status = $StartDISMCommandProgressParameters.Activity
                                                $StartDISMCommandProgressParameters.PercentComplete = (($DISMCommandCounter / $DISMCommandList.Count) * 100) -As [Int]

                                              Write-Progress @StartDISMCommandProgressParameters
    
                                              $StartProcessWithOutputParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                $StartProcessWithOutputParameters.FilePath = "$($System32Directory.FullName)\dism.exe"
                                                $StartProcessWithOutputParameters.ArgumentList = $DISMCommand.Value + ' ' + "/LogPath:`"$($DISMLogDirectory.FullName)\DISM_$($DISMCommand.Key)_Image$($DriverPackageToApplyNumber.ToString('00'))_Index$($DriverPackageImage.ImageIndex.ToString('00')).log`" /LogLevel:$($DISMCommandProperties.LogLevel)"
                                                $StartProcessWithOutputParameters.AcceptableExitCodeList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                  $StartProcessWithOutputParameters.AcceptableExitCodeList.Add(0)
                                                  $StartProcessWithOutputParameters.AcceptableExitCodeList.Add(2)
                                                  $StartProcessWithOutputParameters.AcceptableExitCodeList.Add(50)
                                                $StartProcessWithOutputParameters.CreateNoWindow = $True
                                                $StartProcessWithOutputParameters.LogOutput = $False
                                                $StartProcessWithOutputParameters.Verbose = $True

                                              Switch ($DISMCommand.Key)
                                                {
                                                    {($_ -iin @('UnmountImage'))}
                                                      {
                                                          Switch ($Stage.IsPresent)
                                                            {
                                                                {($_ -eq $True)}
                                                                  {
                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to stage driver content contained within image index $($DriverPackageImage.ImageIndex) locally on this device. Please Wait..."
                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                      Switch (([String]::IsNullOrEmpty($StagingRootDirectory) -eq $True) -or ([String]::IsNullOrWhiteSpace($StagingRootDirectory) -eq $True))
                                                                        {
                                                                            {($_ -eq $True)}
                                                                              {
                                                                                  [System.IO.DirectoryInfo]$DriverPackageStagingRootDirectory = "$($WindowsImageDriveInfo.Name.TrimEnd('\'))\DriverCache"
                                                                              }

                                                                            Default
                                                                              {
                                                                                  [System.IO.DirectoryInfo]$DriverPackageStagingRootDirectory = $StagingRootDirectory.FullName
                                                                              }
                                                                        }
  
                                                                      $CopyItemWithProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                                        $CopyItemWithProgressParameters.Path = $DISMCommandProperties.MountDirectory.FullName
                                                                        $CopyItemWithProgressParameters.Destination = "$($DriverPackageStagingRootDirectory.FullName)\Pkg$($DriverPackageToApplyNumber.ToString('00'))\Index$($DriverPackageImage.ImageIndex.ToString('00'))"
                                                                        $CopyItemWithProgressParameters.Recurse = $True
                                                                        $CopyItemWithProgressParameters.Force = $True
                                                                        $CopyItemWithProgressParameters.SegmentSize = $SegmentSize
                                                                        $CopyItemWithProgressParameters.RandomDelay = $RandomDelay.IsPresent
                                                                        $CopyItemWithProgressParameters.ContinueOnError = $False
                                                                        $CopyItemWithProgressParameters.Verbose = $False

                                                                      $DriverPackageStagingContentList = Copy-ItemWithProgress @CopyItemWithProgressParameters

                                                                      $DriverPackageStagingRootDirectoryDetails = $DriverPackageStagingRootDirectory.FullName -As [System.IO.DirectoryInfo]

                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to hide the driver staging directory of `"$($DriverPackageStagingRootDirectory.FullName)`". Please Wait..."
                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                                                      $DriverPackageStagingRootDirectoryDetails.Attributes = [System.IO.FileAttributes]::Hidden
                                                                  }
                                                            }
                                                        
                                                          $Null = Start-ProcessWithOutput @StartProcessWithOutputParameters
                                                      }

                                                    Default
                                                      {
                                                          $Null = Start-ProcessWithOutput @StartProcessWithOutputParameters
                                                      }
                                                }
                                                
                                              $FinishDISMCommandProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                $FinishDISMCommandProgressParameters.Activity = $StartDISMCommandProgressParameters.Activity
                                                $FinishDISMCommandProgressParameters.Completed = $True

                                              Write-Progress @FinishDISMCommandProgressParameters

                                              $DISMCommandCounter++
                                          }
                                    }
                              }

                            If ([System.IO.Directory]::Exists($WindowsImageMountRootDirectory.FullName) -eq $True)
                              {
                                  $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove directory `"$($WindowsImageMountRootDirectory.FullName)`". Please Wait..."
                                  Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                                  Try {$Null = [System.IO.Directory]::Delete($WindowsImageMountRootDirectory.FullName, $True)} Catch {}
                              }
                        }

                      Default
                        {
                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - $($DriverPackagesToApply.Count) driver package(s) need to be applied to the Windows installation contained on volume `"$($WindowsImageDriveInfo.Name.TrimEnd('\').Toupper())`"."
                            Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                        }
                  }
                              
                #If necessary, create, get, and or set any task sequence variable(s).   
                  Switch ($IsRunningTaskSequence)
                    {
                        {($_ -eq $True)}
                          {            
                              ForEach ($TSVariable In $TSVariableTable.GetEnumerator())
                                {
                                    [String]$TSVariableName = "$($TSVariable.Key)"
                                    [String]$TSVariableCurrentValue = $TSEnvironment.Value($TSVariableName)
                                    [String]$TSVariableNewValue = "$($TSVariable.Value -Join ',')"
                                                  
                                    Switch ($TSVariableCurrentValue -ine $TSVariableNewValue)
                                      {
                                          {($_ -eq $True)}
                                            {
                                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to set the task sequence variable of `"$($TSVariableName)`". Please Wait..."
                                                Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                                      
                                                $Null = $TSEnvironment.Value($TSVariableName) = "$($TSVariableNewValue)" 
                                            }
                                      } 
                                }
                                
                              $Null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($TSEnvironment)       
                          }
                        
                        {($_ -eq $False)}
                          {
                              $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - There is no task sequence running."
                              Write-Verbose -Message ($LoggingDetails.WarningMessage) -Verbose
                          }
                    }

                #Cleanup the driver package download directory
                  If ([System.IO.Directory]::Exists($DriverPackageDownloadDirectory.FullName) -eq $True)
                    {
                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove directory `"$($DriverPackageDownloadDirectory.FullName)`". Please Wait..."
                        Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                        Try {$Null = [System.IO.Directory]::Delete($DriverPackageDownloadDirectory.FullName, $True)} Catch {}
                    }
                  
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