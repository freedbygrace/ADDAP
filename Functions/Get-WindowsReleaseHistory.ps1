## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Get-WindowsReleaseHistory
Function Get-WindowsReleaseHistory
    {
        <#
          .SYNOPSIS
          Retrieves the Windows release history by scraping the release information from the internet
          
          .DESCRIPTION
          Slightly more detailed description of what your function does
                    
          .EXAMPLE
          Get-WindowsReleaseHistory -Verbose

          .EXAMPLE
          Get-WindowsReleaseHistory -Force -Verbose
  
          .NOTES
          a global variable named 'WindowsReleaseHistory' will be created that will store the release details. To keep web request traffic to a minimum, repeat executions of this function will return cached data unless the '-Force' parameter is specified.
          
          $Global:WindowsReleaseHistory

          .LINK
          https://learn.microsoft.com/en-us/windows/release-health/release-information

          .LINK
          https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
        #>
        
        [CmdletBinding()]  
          Param
            (        
                [Parameter(Mandatory=$False)]
                [Switch]$Force,
                                              
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
                    [System.IO.FileInfo]$FunctionPath = $PSCommandPath
                    [System.IO.DirectoryInfo]$FunctionDirectory = "$($FunctionPath.Directory.FullName)"
                      
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is beginning. Please Wait..."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    [String[]]$AvailableScriptParameters = (Get-Command -Name ($FunctionName)).Parameters.GetEnumerator() | Where-Object {($_.Value.Name -inotin $CommonParameterList)} | ForEach-Object {"-$($_.Value.Name):$($_.Value.ParameterType.Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Available Function Parameter(s) = $($AvailableScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    [String[]]$SuppliedScriptParameters = $PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key):$($_.Value.GetType().Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supplied Function Parameter(s) = $($SuppliedScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($FunctionName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    #region Load any required libraries
                      [System.IO.DirectoryInfo]$LibariesDirectory = "$($FunctionDirectory.FullName)\Libraries"

                      Switch ([System.IO.Directory]::Exists($LibariesDirectory.FullName))
                        {
                            {($_ -eq $True)}
                              {
                                  $LibraryPatternList = New-Object -TypeName 'System.Collections.Generic.List[String]'
                                    $LibraryPatternList.Add('HtmlAgilityPack.dll')

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
                                                              
                    #Create an object that will contain the functions output.
                      $OutputObjectList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                    #region Adjust security protocol type(s)
                      [System.Net.SecurityProtocolType]$DesiredSecurityProtocol = [System.Net.SecurityProtocolType]::TLS12
  
                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to set the desired security protocol to `"$($DesiredSecurityProtocol.ToString().ToUpper())`". Please Wait..."
                      Write-Verbose -Message ($LoggingDetails.LogMessage)
          
                      $Null = [System.Net.ServicePointManager]::SecurityProtocol = ($DesiredSecurityProtocol)
                    #endregion

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
                    Switch (($Null -ieq $Global:WindowsReleaseHistory) -or ($Force.IsPresent -eq $True))
                      {
                          {($_ -eq $True)}
                            {
                                $URLList = New-Object -TypeName 'System.Collections.Generic.List[System.URI]'
                                  $URLList.Add('https://learn.microsoft.com/en-us/windows/release-health/release-information')
                                  $URLList.Add('https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information')

                                For ($URLListIndex = 0; $URLListIndex -lt $URLList.Count; $URLListIndex++)
                                  {
                                      $URL = $URLList[$URLListIndex]

                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to retrieve data from `"$($URL.OriginalString)`". Please Wait..."
                                      Write-Verbose -Message ($LoggingDetails.LogMessage)

                                      $HTMLWebRequest = New-Object -TypeName 'HtmlAgilityPack.HtmlWeb'

                                      $HTMLWebRequestObject = $HTMLWebRequest.Load($URL.OriginalString)

                                      $HTMLDocumentObject = $HTMLWebRequestObject.DocumentNode

                                      $MetadataList = $HTMLDocumentObject.SelectNodes('/html/head//meta') | Where-Object {($_.OuterHTML -imatch '.*og\:title.*')}

                                      $OGTitle = ($MetadataList[0].Attributes | Where-Object {($_.Name -ieq 'Content')}).Value
   
                                      $Global:HistoryTableList = $HTMLDocumentObject.SelectNodes('//table') | Where-Object {($_.ID -imatch '(^HistoryTable_\d+$)')}

                                      $RootNodeList = $HTMLDocumentObject.SelectNodes('//strong')

                                      For ($RootNodeListIndex = 0; $RootNodeListIndex -lt $RootNodeList.Count; $RootNodeListIndex++)
                                        {   
                                            $RootNode = $RootNodeList[$RootNodeListIndex]

                                            $RootNodeRegexData = [Regex]::Match($RootNode.InnerText, '(?:.*Version\s+)(?<OSReleaseID>\w{4,4})(?:.*)(?:\s+\(OS\s+build\s+)(?<OSBuild>\d{5,5})(?:.+)')
                        
                                            Switch ($RootNodeRegexData.Success)
                                              {
                                                  {($_ -eq $True)}
                                                    {    
                                                        $OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                                          $OutputObjectProperties.Vendor = 'Microsoft'
                                                          $OutputObjectProperties.Name = [Regex]::Match($OGTitle, 'W.+\d+').Value
                                                          $OutputObjectProperties.ReleaseID = ($RootNodeRegexData.Groups | Where-Object {($_.Name -ieq 'OSReleaseID')}).Value
                                                          $OutputObjectProperties.Build = ($RootNodeRegexData.Groups | Where-Object {($_.Name -ieq 'OSBuild')}).Value
                                                          $OutputObjectProperties.Version = "10.0.$($OutputObjectProperties.Build)" -As [System.Version]
                                                          $OutputObjectProperties.ReleaseHistory = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                                                          <#
                                                          $HistoryTableRowList = ($HistoryTableList.ChildNodes | Where-Object {($_.ChildNodes.Count -gt 0)})

                                                          For ($HistoryTableRowListIndex = 0; $HistoryTableRowListIndex -lt $HistoryTableRowList.Count; $HistoryTableRowListIndex++)
                                                            { 
                                                                $HistoryTableRow = $HistoryTableRowList[$HistoryTableRowListIndex]

                                                                Switch ($HistoryTableRowListIndex)
                                                                  {
                                                                      {($_ -eq 0)}
                                                                        {
                                                                            $HistoryTableRowNodeList = $HistoryTableRow.ChildNodes | Where-Object {([String]::IsNullOrEmpty($_.InnerText) -eq $False) -and ([String]::IsNullOrWhiteSpace($_.InnerText) -eq $False)}
                  
                                                                            $HistoryTableRowPropertyList = ($HistoryTableRowNodeList | ForEach-Object {($TextInfo.ToTitleCase($_.InnerText) -ireplace '(\s+)', '')}) -As [System.Collections.Generic.List[String]]                  
                                                                        }

                                                                      Default
                                                                        {
                                                                            Switch ($HistoryTableRowPropertyList.Count -gt 0)
                                                                              {
                                                                                  {($_ -eq $True)}
                                                                                    {
                                                                                        $ReleaseHistoryObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                              
                                                                                        $HistoryTableRowData = $HistoryTableRow.ChildNodes | Where-Object {($_.ChildNodes.Count -gt 0)}
                              
                                                                                        For ($HistoryTableRowPropertyListIndex = 0; $HistoryTableRowPropertyListIndex -lt $HistoryTableRowPropertyList.Count; $HistoryTableRowPropertyListIndex++)
                                                                                          {
                                                                                              $HistoryTableRowPropertyName = $HistoryTableRowPropertyList[$HistoryTableRowPropertyListIndex]

                                                                                              $HistoryTableRowPropertyValue = $HistoryTableRowData[$HistoryTableRowPropertyListIndex]

                                                                                              Switch ($Null -ine $HistoryTableRowPropertyValue)
                                                                                                {
                                                                                                    {($_ -eq $True)}
                                                                                                      {
                                                                                                          $ValuesMatchingRowNodeList = $HistoryTableRowNodeList | Where-Object {($_.InnerText -imatch ".*$($HistoryTableRowPropertyValue.InnerText).*")}

                                                                                                          $ValuesMatchingRowNodeListCount = ($ValuesMatchingRowNodeList | Measure-Object).Count
                                                
                                                                                                          Switch ($ValuesMatchingRowNodeListCount -eq 0)
                                                                                                            {
                                                                                                                {($_ -eq $True)}
                                                                                                                  {
                                                                                                                      $ReleaseHistoryObjectProperties."$($HistoryTableRowPropertyName)" = $HistoryTableRowPropertyValue.InnerText
                                                                                                                  }

                                                                                                                Default
                                                                                                                  {
                                                                                                                      $ReleaseHistoryObjectProperties."$($HistoryTableRowPropertyName)" = $Null
                                                                                                                  }
                                                                                                            }           
                                                                                                      }
                                                                                                }
                                                                                          }

                                                                                        $ReleaseHistoryObject = New-Object -TypeName 'PSObject' -Property ($ReleaseHistoryObjectProperties)

                                                                                        $OutputObjectProperties.ReleaseHistory.Add($ReleaseHistoryObject)
                                                                                    }
                                                                              }
                                                                        }
                                                                  }
                                                            }
                                                          #>

                                                        $OutputObject = New-Object -TypeName 'PSObject' -Property ($OutputObjectProperties)

                                                        $OutputObjectList.Add($OutputObject)
                                                    }
                                              }
                                        }

                                      $Null = $OutputObjectProperties.ReleaseHistory = $OutputObjectProperties.ReleaseHistory.ToArray() | Where-Object {($Null -ine $_)}
                                  }

                                #Write the object to the powershell pipeline
                                  $OutputObjectList = $OutputObjectList.ToArray()

                                  $Global:WindowsReleaseHistory = $OutputObjectList | Sort-Object -Property @('Version') | Group-Object -Property @('Name')
                            }

                          Default
                            {
                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - The Windows release history has already been retrieved. Returning cached results in order to reduce web request traffic."
                                Write-Warning -Message ($LoggingDetails.WarningMessage)          
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
                      Write-Verbose -Message ($LoggingDetails.LogMessage)

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($FunctionName)`' is completed."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {
                    Write-Output -InputObject ($Global:WindowsReleaseHistory)
                }
          }
    }
#endregion

<#
  Get-WindowsReleaseHistory -Verbose
#>