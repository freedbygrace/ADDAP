## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Invoke-ScheduledTaskAction
Function Invoke-ScheduledTaskAction
    {
        <#
          .SYNOPSIS
          A brief overview of what your function does
          
          .DESCRIPTION
          Slightly more detailed description of what your function does
          
        .PARAMETER Create
	        Your parameter description

        .PARAMETER ScheduledTaskDefinition
	        Your parameter description

        .PARAMETER Force
	        Your parameter description

        .PARAMETER Remove
	        Your parameter description

        .PARAMETER ScheduledTaskFolder
	        Your parameter description

        .PARAMETER ScheduledTaskName
	        Your parameter description

        .PARAMETER Source
	        Your parameter description

        .PARAMETER Destination
	        Your parameter description

        .PARAMETER ScriptName
	        Your parameter description

        .PARAMETER ScriptParameters
	        Your parameter description

        .PARAMETER Stage
	        Your parameter description

        .PARAMETER Execute
	        Your parameter description

        .PARAMETER ContinueOnError
	        Your parameter description
          
          .EXAMPLE
          [System.IO.FileInfo]$ScheduledTaskDefinitionPath = 'C:\YourPath\YourExportedScheduledTask.xml'

          [String]$ScheduledTaskDefinition = [System.IO.File]::ReadAllText($ScheduledTaskDefinitionPath.FullName)

          $InvokeScheduledTaskActionParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
	          $InvokeScheduledTaskActionParameters.Create = $True
	          $InvokeScheduledTaskActionParameters.ScheduledTaskDefinition = $ScheduledTaskDefinition
	          $InvokeScheduledTaskActionParameters.Force = $True
	          $InvokeScheduledTaskActionParameters.ScheduledTaskFolder = "\YourScheduledTaskFolder"
	          $InvokeScheduledTaskActionParameters.ScheduledTaskName = "Your Scheduled Task Name"
	          $InvokeScheduledTaskActionParameters.Source = "\\YourServer\YourShare\YourScriptDirectory"   
	          $InvokeScheduledTaskActionParameters.ScriptName = "YourPowershellScript.ps1"
            $InvokeScheduledTaskActionParameters.ScriptParameters = New-Object -TypeName 'System.Collections.Generic.List[String]'
              $InvokeScheduledTaskActionParameters.ScriptParameters.Add('-Verbose')
              $InvokeScheduledTaskActionParameters.ScriptParameters = $InvokeScheduledTaskActionParameters.ScriptParameters.ToArray()    
            $InvokeScheduledTaskActionParameters.Destination = "$($Env:ProgramData)\ScheduledTasks\$([System.IO.Path]::GetFileNameWithoutExtension($InvokeScheduledTaskActionParameters.ScriptName))"
            $InvokeScheduledTaskActionParameters.Stage = $True
	          $InvokeScheduledTaskActionParameters.Execute = $False
	          $InvokeScheduledTaskActionParameters.ContinueOnError = $False
	          $InvokeScheduledTaskActionParameters.Verbose = $True

          $InvokeScheduledTaskActionResult = Invoke-ScheduledTaskAction @InvokeScheduledTaskActionParameters

          Write-Output -InputObject ($InvokeScheduledTaskActionResult)

          .EXAMPLE
          Invoke-ScheduledTaskAction -Remove -ScheduledTaskFolder '\Custom' -ScheduledTaskName 'Perform Dynamic Software Removal' -Source "$($Env:ProgramData)\ScheduledTasks\Invoke-SoftwareRemoval" -Verbose
  
          .NOTES
          This function uses an older, but more compatible method of creating scheduled tasks.
          
          .LINK
          https://learn.microsoft.com/en-us/windows/win32/taskschd/schtasks

          .LINK
          https://ss64.com/nt/schtasks.html
        #>
        
        [CmdletBinding(ConfirmImpact = 'Low', DefaultParameterSetName = 'Create', HelpURI = '', SupportsShouldProcess = $True)]
       
        Param
          (        
              [Parameter(Mandatory=$True, ParameterSetName = 'Create')]
              [Alias('C')]
              [Switch]$Create,

              [Parameter(Mandatory=$True, ParameterSetName = 'Create')]
              [ValidateNotNullOrEmpty()]
              [Alias('STD')]
              [String]$ScheduledTaskDefinition,
 
              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [Alias('F')]
              [Switch]$Force,

              [Parameter(Mandatory=$True, ParameterSetName = 'Remove')]
              [Alias('R')]
              [Switch]$Remove,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [Parameter(Mandatory=$False, ParameterSetName = 'Remove')]
              [ValidateNotNullOrEmpty()]
              [ValidateScript({$_.StartsWith('\')})]
              [Alias('STF')]
              [String]$ScheduledTaskFolder,

              [Parameter(Mandatory=$True, ParameterSetName = 'Create')]
              [Parameter(Mandatory=$True, ParameterSetName = 'Remove')]
              [ValidateNotNullOrEmpty()]
              [Alias('STN')]
              [String]$ScheduledTaskName,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [Parameter(Mandatory=$False, ParameterSetName = 'Remove')]
              [ValidateNotNullOrEmpty()]
              [Alias('SD')]
              [System.IO.DirectoryInfo]$Source,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [ValidateNotNullOrEmpty()]
              [Alias('DD')]
              [System.IO.DirectoryInfo]$Destination,

              [Parameter(Mandatory=$True, ParameterSetName = 'Create')]
              [ValidateNotNullOrEmpty()]
              [Alias('SN')]
              [ValidateScript({$_ -imatch '^.*\.(bat|cmd|ps1|vbs|wsf)$'})]
              [String]$ScriptName,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [AllowEmptyCollection()]
              [AllowNull()]
              [Alias('SP')]
              [String[]]$ScriptParameters,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [Alias('S')]
              [Switch]$Stage,

              [Parameter(Mandatory=$False, ParameterSetName = 'Create')]
              [Alias('E')]
              [Switch]$Execute,
                                            
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError        
          )
                    
        Begin
          {

              
              Try
                {
                    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss.FFF tt'  ###Monday, January 01, 2019 @ 10:15:34.000 AM###
                    [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
                    $DateTimeMessageFormat = 'MM/dd/yyyy HH:mm:ss.FFF'  ###03/23/2022 11:12:48.347###
                    [ScriptBlock]$GetCurrentDateTimeMessageFormat = {(Get-Date).ToString($DateTimeMessageFormat)}
                    $DateFileFormat = 'yyyyMMdd'  ###20190403###
                    [ScriptBlock]$GetCurrentDateFileFormat = {(Get-Date).ToString($DateFileFormat)}
                    $DateTimeFileFormat = 'yyyyMMdd_HHmmss'  ###20190403_115354###
                    [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
                    $TextInfo = (Get-Culture).TextInfo
                    $LoggingDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'    
                      $LoggingDetails.Add('LogMessage', $Null)
                      $LoggingDetails.Add('WarningMessage', $Null)
                      $LoggingDetails.Add('ErrorMessage', $Null)
                    $CommonParameterList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                      $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::CommonParameters)
                      $CommonParameterList.AddRange([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
                    $ParameterSetName = $PSCmdlet.ParameterSetName

                    [ScriptBlock]$ErrorHandlingDefinition = {
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
                                                                      Write-Warning -Message ($LoggingDetails.ErrorMessage)
                                                                  }

                                                                Switch (($ContinueOnError.IsPresent -eq $False) -or ($ContinueOnError -eq $False))
                                                                  {
                                                                      {($_ -eq $True)}
                                                                        {                  
                                                                            Throw
                                                                        }
                                                                  }
                                                            }
                    
                    #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                    
                    [String]$FunctionName = $MyInvocation.MyCommand
                    [System.IO.FileInfo]$InvokingScriptPath = $MyInvocation.PSCommandPath
                    [System.IO.DirectoryInfo]$InvokingScriptDirectory = $InvokingScriptPath.Directory.FullName
                    [System.IO.FileInfo]$FunctionPath = "$($InvokingScriptDirectory.FullName)\Functions\$($FunctionName).ps1"
                    [System.IO.DirectoryInfo]$FunctionDirectory = "$($FunctionPath.Directory.FullName)"
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is beginning. Please Wait..."
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    [String[]]$AvailableScriptParameters = (Get-Command -Name ($FunctionName)).Parameters.GetEnumerator() | Where-Object {($_.Value.Name -inotin $CommonParameterList)} | ForEach-Object {"-$($_.Value.Name):$($_.Value.ParameterType.Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Available Function Parameter(s) = $($AvailableScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                    [String[]]$SuppliedScriptParameters = $PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key):$($_.Value.GetType().Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supplied Function Parameter(s) = $($SuppliedScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($FunctionName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Parameter Set Name: $($ParameterSetName)"
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                                        
                    #Create an object that will contain the functions output.
                      $OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

                    #Define additional variable(s)
                      [System.IO.DirectoryInfo]$DefaultStagingDirectory = "$($Env:ProgramData)\ScheduledTasks\$([System.IO.Path]::GetFileNameWithoutExtension($ScriptName))"

                    #Define default parameter value(s)
                      Switch ($True)
                        {
                            {([String]::IsNullOrEmpty($ScheduledTaskFolder) -eq $True) -or ([String]::IsNullOrWhiteSpace($ScheduledTaskFolder) -eq $True)}
                              {
                                  $ScheduledTaskFolder = '\'
                              }

                            {([String]::IsNullOrEmpty($Destination) -eq $True) -or ([String]::IsNullOrWhiteSpace($Destination) -eq $True)}
                              {
                                  [System.IO.DirectoryInfo]$Destination = $DefaultStagingDirectory.FullName
                              }

                            {($ParameterSetName -iin @('Remove')) -and ([String]::IsNullOrEmpty($Source) -eq $True) -or ([String]::IsNullOrWhiteSpace($Source) -eq $True)}
                              {
                                  [System.IO.DirectoryInfo]$Source = $DefaultStagingDirectory.FullName
                              }
                        }
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    
                }
          }

        Process
          {           
              Try
                {  
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to retrieve the list of scheduled task(s). Please Wait..."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $GetScheduledTaskListResult = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                    
                    $Process = New-Object -TypeName 'System.Diagnostics.Process'
                      $Process.StartInfo.FileName = "$([System.Environment]::SystemDirectory)\schtasks.exe"
                      $Process.StartInfo.UseShellExecute = $False          
                      $Process.StartInfo.RedirectStandardOutput = $True
                      $Process.StartInfo.RedirectStandardError = $True
                      $Process.StartInfo.CreateNoWindow = $True
                      $Process.StartInfo.Arguments = "/Query /FO CSV"

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to execute command: `"$($Process.StartInfo.FileName)`" $($Process.StartInfo.Arguments)"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $Null = $Process.Start()
      
                    $GetScheduledTaskListResult.StandardOutput = $Process.StandardOutput.ReadToEnd()
                    $GetScheduledTaskListResult.StandardError = $Process.StandardError.ReadToEnd()
    
                    $Null = $Process.WaitForExit()

                    $GetScheduledTaskListResult.ExitCode = $Process.ExitCode

                    Switch ($GetScheduledTaskListResult.ExitCode -iin @(0))
                      {
                          {($_ -eq $True)}
                            {
                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The command execution was successful. [Exit Code: $($GetScheduledTaskListResult.ExitCode)]"
                                Write-Verbose -Message ($LoggingDetails.LogMessage)

                                $ScheduledTaskObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                                
                                $ScheduledTaskList = $GetScheduledTaskListResult.StandardOutput | ConvertFrom-CSV -Delimiter ',' | Where-Object {($_.TaskName -inotmatch '(^TaskName$)')} | Sort-Object -Property @('TaskName') -Unique
                                
                                ForEach ($ScheduledTask In $ScheduledTaskList)
                                  {                                      
                                      $ScheduledTaskObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                        $ScheduledTaskObjectProperties.TaskFolder = Split-Path -Path $ScheduledTask.TaskName -Parent
                                        $ScheduledTaskObjectProperties.TaskName = Split-Path -Path $ScheduledTask.TaskName -Leaf
                                        $ScheduledTaskObjectProperties.TaskSchedulerPath = $Null
                                        $ScheduledTaskObjectProperties.Status = $ScheduledTask.Status
                                        $ScheduledTaskObjectProperties.NextRunTime = $Null
                                            
                                      Switch (($ScheduledTaskObjectProperties.TaskFolder -ieq '\'))
                                        {
                                            {($_ -eq $True)}
                                              {
                                                  $ScheduledTaskObjectProperties.TaskFolder = '\'

                                                  $ScheduledTaskObjectProperties.TaskSchedulerPath = "$($ScheduledTaskObjectProperties.TaskFolder)$($ScheduledTaskObjectProperties.TaskName)"
                                              }

                                            Default
                                              {
                                                  $ScheduledTaskObjectProperties.TaskFolder = $ScheduledTaskObjectProperties.TaskFolder.TrimStart('\').TrimEnd('\')

                                                  $ScheduledTaskObjectProperties.TaskSchedulerPath = "\$($ScheduledTaskObjectProperties.TaskFolder)\$($ScheduledTaskObjectProperties.TaskName)"
                                              }
                                        }
                                      
                                      $DateTime = New-Object -TypeName 'DateTime'

                                      $DateTimeProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                        $DateTimeProperties.Input = $ScheduledTask.'Next Run Time'
                                        $DateTimeProperties.FormatList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                          $DateTimeProperties.FormatList.AddRange(([System.Globalization.DateTimeFormatInfo]::CurrentInfo.GetAllDateTimePatterns()))
                                          $DateTimeProperties.FormatList.AddRange(([System.Globalization.DateTimeFormatInfo]::InvariantInfo.GetAllDateTimePatterns()))
                                          $DateTimeProperties.FormatList.Add('yyyyMM')
                                          $DateTimeProperties.FormatList.Add('yyyyMMdd')
                                        $DateTimeProperties.Culture = $Null
                                        $DateTimeProperties.Styles = New-Object -TypeName 'System.Collections.Generic.List[System.Globalization.DateTimeStyles]'
                                          $DateTimeProperties.Styles.Add([System.Globalization.DateTimeStyles]::AllowWhiteSpaces)
                                        $DateTimeProperties.Successful = [DateTime]::TryParseExact($DateTimeProperties.Input, $DateTimeProperties.FormatList, $DateTimeProperties.Culture, $DateTimeProperties.Styles.ToArray(), [Ref]$DateTime)
                                        $DateTimeProperties.DateTime = $DateTime

                                      $DateTimeObject = New-Object -TypeName 'PSObject' -Property ($DateTimeProperties)

                                      Switch ($DateTimeProperties.Successful)
                                        {
                                            {($_ -eq $True)}
                                              {
                                                  $ScheduledTaskObjectProperties.NextRunTime = $DateTimeObject.DateTime
                                              }
                                        }

                                      $ScheduledTaskObject = New-Object -TypeName 'PSObject' -Property ($ScheduledTaskObjectProperties)

                                      $ScheduledTaskObjectList.Add($ScheduledTaskObject)
                                  }
                                
                                $ScheduledTaskObjectList = $ScheduledTaskObjectList | Sort-Object -Property @('TaskFolder', 'TaskName')

                                $OutputObjectProperties.ScheduledTaskList = $ScheduledTaskObjectList
   
                                $ExistingScheduledTask = $ScheduledTaskObjectList | Where-Object {($_.TaskFolder -ieq $ScheduledTaskFolder.TrimStart('\')) -and ($_.TaskName -ieq $ScheduledTaskName)}

                                $ExistingScheduledTaskCount = ($ExistingScheduledTask | Measure-Object).Count

                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Located $($ExistingScheduledTaskCount) scheduled task(s) located within the folder of `"$($ScheduledTaskFolder)`" with a task name of `"$($ScheduledTaskName)`"."
                                Write-Verbose -Message ($LoggingDetails.LogMessage)

                                [String]$ScheduledTaskLocation = "$($ScheduledTaskFolder)\$($ScheduledTaskName)"

                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Desired Scheduled Task Location: $($ScheduledTaskLocation)"
                                Write-Verbose -Message ($LoggingDetails.LogMessage)
                                    
                                Switch ($ParameterSetName)
                                  {
                                      {($_ -iin @('Create'))}
                                        {
                                            [System.IO.FileInfo]$ScriptSourcePath = "$($Source.FullName)\$($ScriptName)"

                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script Source Path: $($ScriptSourcePath.FullName)"
                                            Write-Verbose -Message ($LoggingDetails.LogMessage)

                                            [System.IO.FileInfo]$ScriptDestinationPath = "$($Destination.FullName)\$($ScriptName)"

                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script Destination Path: $($ScriptDestinationPath.FullName)"
                                            Write-Verbose -Message ($LoggingDetails.LogMessage)
                                            
                                            Switch (($ExistingScheduledTaskCount -eq 0) -or ($Force.IsPresent -eq $True))
                                              {
                                                  {($_ -eq $True)}
                                                    {
                                                        $XMLConfigurationTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $XMLConfigurationTable.Content = $ScheduledTaskDefinition
                                                          $XMLConfigurationTable.Document = New-Object -TypeName 'System.XML.XMLDocument'
                                                            $XMLConfigurationTable.Document.LoadXML($XMLConfigurationTable.Content)

                                                        $CommandExecutionObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                                                        
                                                        Switch ($Stage.IsPresent)
                                                          {
                                                              {($_ -eq $True)}
                                                                {
                                                                    $ArgumentsNodeValueList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                                    
                                                                    Switch ($ScriptSourcePath.Extension)
                                                                      {
                                                                          {($_ -iin @('.bat', '.cmd'))}
                                                                            {
                                                                                $CommandNodeValue = "`"$([System.Environment]::SystemDirectory)\cmd.exe`""
                                                                                
                                                                                $ArgumentsNodeValueList.Add('/c')
                                                                                $ArgumentsNodeValueList.Add("`"$($ScriptDestinationPath.FullName)`"")
                                                                                
                                                                                Switch ($ScriptParameters.Count -gt 0)
                                                                                  {
                                                                                      {($_ -eq $True)}
                                                                                        {
                                                                                            ForEach ($ScriptParameter In $ScriptParameters)
                                                                                              {
                                                                                                  $ArgumentsNodeValueList.Add($ScriptParameter)
                                                                                              }
                                                                                        }
                                                                                  }      
                                                                            }
                                                                                
                                                                          {($_ -iin @('.ps1'))}
                                                                            {
                                                                                $CommandNodeValue = "`"$([System.Environment]::SystemDirectory)\WindowsPowerShell\v1.0\powershell.exe`""
                                                                                 
                                                                                $ArgumentsNodeValueList.Add('-ExecutionPolicy Bypass')
                                                                                $ArgumentsNodeValueList.Add('-NonInteractive')
                                                                                $ArgumentsNodeValueList.Add('-NoProfile')
                                                                                $ArgumentsNodeValueList.Add('-NoLogo')
                                                                                $ArgumentsNodeValueList.Add('-WindowStyle Hidden')
                                                                                $ArgumentsNodeValueList.Add('-Command')
                                                                                $ArgumentsNodeValueList.Add("`"& '$($ScriptDestinationPath.FullName)'")

                                                                                Switch ($ScriptParameters.Count -gt 0)
                                                                                  {
                                                                                      {($_ -eq $True)}
                                                                                        {
                                                                                            ForEach ($ScriptParameter In $ScriptParameters)
                                                                                              {
                                                                                                  $ArgumentsNodeValueList.Add($ScriptParameter)
                                                                                              }
                                                                                        }
                                                                                  }

                                                                                $ArgumentsNodeValueListTargetIndex = $ArgumentsNodeValueList.Count - 1

                                                                                $ArgumentsNodeValueListIndexItem = $ArgumentsNodeValueList[$ArgumentsNodeValueListTargetIndex]

                                                                                $Null = $ArgumentsNodeValueList.RemoveAt($ArgumentsNodeValueListTargetIndex)
 
                                                                                $Null = $ArgumentsNodeValueList.Insert($ArgumentsNodeValueListTargetIndex, ($ArgumentsNodeValueListIndexItem + ';'))

                                                                                $ArgumentsNodeValueList.Add("[System.Environment]::Exit((`$LASTEXITCODE -Bor [Int](-Not `$? -And -Not `$LASTEXITCODE)))`"")
                                                                            }
                                                                            
                                                                          {($_ -iin @('.vbs', '.wsf'))}
                                                                            {
                                                                                $CommandNodeValue = "`"$([System.Environment]::SystemDirectory)\cscript.exe`""
                                                                                     
                                                                                $ArgumentsNodeValueList.Add('//nologo')
                                                                                $ArgumentsNodeValueList.Add('//B')
                                                                                $ArgumentsNodeValueList.Add("`"$($ScriptDestinationPath.FullName)`"")
                                                                                
                                                                                Switch ($ScriptParameters.Count -gt 0)
                                                                                  {
                                                                                      {($_ -eq $True)}
                                                                                        {
                                                                                            ForEach ($ScriptParameter In $ScriptParameters)
                                                                                              {
                                                                                                  $ArgumentsNodeValueList.Add($ScriptParameter)
                                                                                              }
                                                                                        }
                                                                                  }         
                                                                            }   
                                                                      }

                                                                    Switch (([String]::IsNullOrEmpty($CommandNodeValue) -eq $False) -and ([String]::IsNullOrWhiteSpace($CommandNodeValue) -eq $False))
                                                                      {
                                                                          {($_ -eq $True)}
                                                                            {
                                                                                Switch ($ArgumentsNodeValueList.Count -gt 0)
                                                                                  {
                                                                                      {($_ -eq $True)}
                                                                                        {   
                                                                                            $ArgumentsNodeValue = $ArgumentsNodeValueList -Join ' '

                                                                                            $ScheduledTaskNamespaceURI = $XMLConfigurationTable.Document.Task.NamespaceURI

                                                                                            $ActionsNodeList = $XMLConfigurationTable.Document.Task.ChildNodes | Where-Object {($_.Name -iin @('Actions'))}

                                                                                            Switch ($Null -ieq $ActionsNodeList)
                                                                                              {
                                                                                                  {($_ -eq $True)}
                                                                                                    {
                                                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add the `"Actions`" node. Please Wait..."
                                                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                                
                                                                                                        $ActionsNode = $XMLConfigurationTable.Document.Task.AppendChild($XMLConfigurationTable.Document.CreateElement('Actions', $ScheduledTaskNamespaceURI))

                                                                                                        $Null = $ActionsNode.SetAttribute('Context', 'Author')
                                                                                                    }

                                                                                                  Default
                                                                                                    {
                                                                                                        $ActionsNode = $XMLConfigurationTable.Document.Task.Actions    
                                                                                                    }
                                                                                              }

                                                                                            $ExecutionNodeList = $ActionsNode.Exec

                                                                                            $ExecutionNodeListCount = ($ExecutionNodeList | Measure-Object).Count

                                                                                            Switch ($ExecutionNodeListCount)
                                                                                              {
                                                                                                  {($_ -gt 0)}
                                                                                                    {
                                                                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove all $($ActionsNode.ChildNodes.Count) child node(s) from underneath of the `"Actions`" node. Please Wait..."
                                                                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                        
                                                                                                        $Null = $ActionsNode.RemoveAll()
                                                                                                    }
                                                                                              }
                                                                      
                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to add an `"Exec`" node to the scheduled task definition to initiate script execution. Please Wait..."
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Command: $($CommandNodeValue)"
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Arguments: $($ArgumentsNodeValue)"
                                                                                            Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                    
                                                                                            $ExecutionNode = $ActionsNode.AppendChild($XMLConfigurationTable.Document.CreateElement('Exec', $ScheduledTaskNamespaceURI))
     
                                                                                            $CommandNode = $ExecutionNode.AppendChild($XMLConfigurationTable.Document.CreateElement('Command', $ScheduledTaskNamespaceURI))
                                                                                              $Null = $CommandNode.AppendChild($XMLConfigurationTable.Document.CreateTextNode($CommandNodeValue))
  
                                                                                            $ArgumentsNode = $ExecutionNode.AppendChild($XMLConfigurationTable.Document.CreateElement('Arguments', $ScheduledTaskNamespaceURI))
                                                                                              $Null = $ArgumentsNode.AppendChild($XMLConfigurationTable.Document.CreateTextNode($ArgumentsNodeValue))
                                                                                        }

                                                                                      Default
                                                                                        {
                                                                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The argument list could not be determined for the `"$($ScriptName)`" script." 
                                                                                            Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                                        }
                                                                                  }
                                                                            }

                                                                          Default
                                                                            {
                                                                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The command could not be determined for the `"$($ScriptName)`" script." 
                                                                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose
                                                                            }
                                                                      }
                                                                }
                                                          }

                                                        [System.IO.FileInfo]$ScheduledTaskDefinitionPath = "$($Env:Temp.TrimEnd('\'))\$($FunctionName).xml"
                                                                    
                                                        Switch ([System.IO.Directory]::Exists($ScheduledTaskDefinitionPath.Directory.FullName))
                                                          {
                                                              {($_ -eq $False)}
                                                                {
                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create the scheduled task definition export directory of `"$($ScheduledTaskDefinitionPath.Directory.FullName)`". Please Wait..."
                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                        
                                                                    $Null = [System.IO.Directory]::CreateDirectory($ScheduledTaskDefinitionPath.Directory.FullName)
                                                                }
                                                          }
                                                                      
                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to export the scheduled task definition of `"$($ScheduledTaskDefinitionPath.FullName)`". Please Wait..."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                            
                                                        $Null = $XMLConfigurationTable.Document.Save($ScheduledTaskDefinitionPath.FullName)
                                                                    
                                                        $Null = Start-Sleep -Seconds 2
                                                                    
                                                        $CommandExecutionObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                                                                    
                                                        $CommandExecutionProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $CommandExecutionProperties.Condition = ($Stage.IsPresent -eq $True) -and ([System.IO.Directory]::Exists($Source.FullName))
                                                          $CommandExecutionProperties.Command = "$([System.Environment]::SystemDirectory)\robocopy.exe"
                                                          $CommandExecutionProperties.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScriptSourcePath.Directory.FullName)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScriptDestinationPath.Directory.FullName)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add('/E')
                                                            $CommandExecutionProperties.ArgumentList.Add('/PURGE')
                                                            $CommandExecutionProperties.ArgumentList.Add('/Z')
                                                            $CommandExecutionProperties.ArgumentList.Add('/ZB')
                                                            $CommandExecutionProperties.ArgumentList.Add('/W:5')
                                                            $CommandExecutionProperties.ArgumentList.Add('/R:3')
                                                            $CommandExecutionProperties.ArgumentList.Add('/J')
                                                            $CommandExecutionProperties.ArgumentList.Add('/NP')
                                                            $CommandExecutionProperties.ArgumentList.Add('/FP')
                                                            $CommandExecutionProperties.ArgumentList.Add('/TS')
                                                            $CommandExecutionProperties.ArgumentList.Add('/NDL')
                                                            $CommandExecutionProperties.ArgumentList.Add('/TEE')
                                                            $CommandExecutionProperties.ArgumentList.Add('/MT:8')
                                                          $CommandExecutionProperties.AcceptableExitCodes = @(0, 1, 2, 3, 4, 5, 6, 7, 8)
                                                        $CommandExecutionEntry = New-Object -TypeName 'PSObject' -Property ($CommandExecutionProperties)
                                                        $CommandExecutionObjectList.Add($CommandExecutionEntry)
                                                                    
                                                        $CommandExecutionProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $CommandExecutionProperties.Condition = $Create.IsPresent
                                                          $CommandExecutionProperties.Command = "$([System.Environment]::SystemDirectory)\schtasks.exe"
                                                          $CommandExecutionProperties.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                            $CommandExecutionProperties.ArgumentList.Add('/Create')
                                                            $CommandExecutionProperties.ArgumentList.Add('/XML')
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScheduledTaskDefinitionPath.FullName)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add('/TN')
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScheduledTaskLocation)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add('/F')
                                                          $CommandExecutionProperties.AcceptableExitCodes = @(0)
                                                        $CommandExecutionEntry = New-Object -TypeName 'PSObject' -Property ($CommandExecutionProperties)
                                                        $CommandExecutionObjectList.Add($CommandExecutionEntry)
                                                                    
                                                        $CommandExecutionProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $CommandExecutionProperties.Condition = $Execute.IsPresent
                                                          $CommandExecutionProperties.Command = "$([System.Environment]::SystemDirectory)\schtasks.exe"
                                                          $CommandExecutionProperties.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                            $CommandExecutionProperties.ArgumentList.Add('/Run')
                                                            $CommandExecutionProperties.ArgumentList.Add('/TN')
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScheduledTaskLocation)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add('/I')
                                                          $CommandExecutionProperties.AcceptableExitCodes = @(0)
                                                        $CommandExecutionEntry = New-Object -TypeName 'PSObject' -Property ($CommandExecutionProperties)
                                                        $CommandExecutionObjectList.Add($CommandExecutionEntry)
                                                                    
                                                        ForEach ($CommandExecutionObject In $CommandExecutionObjectList)
                                                          {
                                                              Switch ($CommandExecutionObject.Condition)
                                                                {
                                                                    {($_ -eq $True)}
                                                                      {
                                                                          $Process = New-Object -TypeName 'System.Diagnostics.Process'
                                                                            $Process.StartInfo.FileName = "$($CommandExecutionObject.Command)"
                                                                            $Process.StartInfo.UseShellExecute = $False          
                                                                            $Process.StartInfo.RedirectStandardOutput = $False
                                                                            $Process.StartInfo.RedirectStandardError = $False
                                                                            $Process.StartInfo.CreateNoWindow = $True
                                                                            $Process.StartInfo.Arguments = "$($CommandExecutionObject.ArgumentList -Join ' ')"

                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to execute command: `"$($Process.StartInfo.FileName)`" $($Process.StartInfo.Arguments)"
                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                                          $Null = $Process.Start()
          
                                                                          $Null = $Process.WaitForExit()
                                                                          
                                                                          Switch ($Process.ExitCode -in $CommandExecutionObject.AcceptableExitCodes)
                                                                            {
                                                                                {($_ -eq $True)}
                                                                                  {
                                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The command execution was successful. [Exit Code: $($Process.ExitCode)]"
                                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                                  }

                                                                                Default
                                                                                  {
                                                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  The command execution was unsuccessful. [Exit Code: $($Process.ExitCode)]" 
                                                                                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                                                                      $ErrorMessage = "$($LoggingDetails.WarningMessage)"
                                                                                      $Exception = [System.Exception]::New($ErrorMessage)           
                                                                                      $ErrorRecord = [System.Management.Automation.ErrorRecord]::New($Exception, [System.Management.Automation.ErrorCategory]::InvalidResult.ToString(), [System.Management.Automation.ErrorCategory]::InvalidResult, $Process)

                                                                                      $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                                                                                  }
                                                                            }
                                                                      }

                                                                    Default
                                                                      {
                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Skipping the command execution of `"$($CommandExecutionObject.Command)`" $($CommandExecutionObject.ArgumentList -Join ' ')"
                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                      }
                                                                }    
                                                          }
                                                                    
                                                        $Null = Start-Sleep -Seconds 2
                                                                    
                                                        Switch ([System.IO.File]::Exists($ScheduledTaskDefinitionPath.FullName))
                                                          {
                                                              {($_ -eq $True)}
                                                                {
                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to delete the exported scheduled task definition of `"$($ScheduledTaskDefinitionPath.FullName)`". Please Wait..."
                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                        
                                                                    $Null = [System.IO.File]::Delete($ScheduledTaskDefinitionPath.FullName)
                                                                }
                                                          }
                                                    }

                                                  Default
                                                    {
                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The specified scheduled task already exist(s)."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Scheduled Task Folder: $($ScheduledTaskFolder)"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Scheduled Task Name: $($ScheduledTaskName)"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                    }
                                              }
                                        }

                                      {($_ -iin @('Remove'))}
                                        {
                                            Switch ($ExistingScheduledTaskCount -gt 0)
                                              {
                                                  {($_ -eq $True)}
                                                    {                                                        
                                                        $CommandExecutionObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                                                        $CommandExecutionProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $CommandExecutionProperties.Condition = $Remove.IsPresent
                                                          $CommandExecutionProperties.Command = "$([System.Environment]::SystemDirectory)\schtasks.exe"
                                                          $CommandExecutionProperties.ArgumentList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                                            $CommandExecutionProperties.ArgumentList.Add('/Delete')
                                                            $CommandExecutionProperties.ArgumentList.Add('/TN')
                                                            $CommandExecutionProperties.ArgumentList.Add("`"$($ScheduledTaskLocation)`"")
                                                            $CommandExecutionProperties.ArgumentList.Add('/F')
                                                          $CommandExecutionProperties.AcceptableExitCodes = @(0)
                                                        $CommandExecutionEntry = New-Object -TypeName 'PSObject' -Property ($CommandExecutionProperties)
                                                        $CommandExecutionObjectList.Add($CommandExecutionEntry)

                                                        ForEach ($CommandExecutionObject In $CommandExecutionObjectList)
                                                          {
                                                              Switch ($CommandExecutionObject.Condition)
                                                                {
                                                                    {($_ -eq $True)}
                                                                      {
                                                                          $Process = New-Object -TypeName 'System.Diagnostics.Process'
                                                                            $Process.StartInfo.FileName = "$($CommandExecutionObject.Command)"
                                                                            $Process.StartInfo.UseShellExecute = $False          
                                                                            $Process.StartInfo.RedirectStandardOutput = $False
                                                                            $Process.StartInfo.RedirectStandardError = $False
                                                                            $Process.StartInfo.CreateNoWindow = $True
                                                                            $Process.StartInfo.Arguments = "$($CommandExecutionObject.ArgumentList -Join ' ')"

                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to execute command: `"$($Process.StartInfo.FileName)`" $($Process.StartInfo.Arguments)"
                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                                          $Null = $Process.Start()
          
                                                                          $Null = $Process.WaitForExit()
                                                                          
                                                                          Switch ($Process.ExitCode -in $CommandExecutionObject.AcceptableExitCodes)
                                                                            {
                                                                                {($_ -eq $True)}
                                                                                  {
                                                                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The command execution was successful. [Exit Code: $($Process.ExitCode)]"
                                                                                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                                  }

                                                                                Default
                                                                                  {
                                                                                      $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  The command execution was unsuccessful. [Exit Code: $($Process.ExitCode)]" 
                                                                                      Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                                                                      $ErrorMessage = "$($LoggingDetails.WarningMessage)"
                                                                                      $Exception = [System.Exception]::New($ErrorMessage)           
                                                                                      $ErrorRecord = [System.Management.Automation.ErrorRecord]::New($Exception, [System.Management.Automation.ErrorCategory]::InvalidResult.ToString(), [System.Management.Automation.ErrorCategory]::InvalidResult, $Process)

                                                                                      $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                                                                                  }
                                                                            }
                                                                      }

                                                                    Default
                                                                      {
                                                                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Skipping the command execution of `"$($CommandExecutionObject.Command)`" $($CommandExecutionObject.ArgumentList -Join ' ')"
                                                                          Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                      }
                                                                }    
                                                          }

                                                        $Null = Start-Sleep -Seconds 2

                                                        Switch ([System.IO.Directory]::Exists($Source.FullName))
                                                          {
                                                              {($_ -eq $True)}
                                                                {
                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Script Source Path: $($Source.FullName)"
                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                    
                                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to remove scheduled task content directory `"$($Source.FullName)`". Please Wait..."
                                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                                    $Null = [System.IO.Directory]::Delete($Source.FullName, $True)
                                                                }
                                                          }    
                                                    }

                                                  Default
                                                    {
                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The scheduled task of `"$($ScheduledTaskLocation)`" does not exist. No further action will be taken."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                    }
                                              }
                                        }
                                  }
                            }

                          {($_ -eq $False)}
                            {
                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) -  The command execution was unsuccessful. [Exit Code: $($GetScheduledTaskListResult.ExitCode)]" 
                                Write-Warning -Message ($LoggingDetails.WarningMessage) -Verbose

                                $ErrorMessage = "$($LoggingDetails.WarningMessage)"
                                $Exception = [System.Exception]::New($ErrorMessage)           
                                $ErrorRecord = [System.Management.Automation.ErrorRecord]::New($Exception, [System.Management.Automation.ErrorCategory]::InvalidResult.ToString(), [System.Management.Automation.ErrorCategory]::InvalidResult, $Process)

                                $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                            }
                      }
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    
                }
          }
        
        End
          {                                        
              Try
                {
                    #Determine the date and time the function completed execution
                      $FunctionEndTime = (Get-Date)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($FunctionName) ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is completed."
                    Write-Verbose -Message ($LoggingDetails.LogMessage) -Verbose
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    #Write the object to the powershell pipeline
                      $OutputObject = New-Object -TypeName 'PSObject' -Property ($OutputObjectProperties)

                      Write-Output -InputObject ($OutputObject)
                }
          }
    }
#endregion