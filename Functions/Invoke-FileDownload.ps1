## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Invoke-FileDownload
Function Invoke-FileDownload
    {
        <#
          .SYNOPSIS
          Downloads the specified URL.
          
          .DESCRIPTION
          The file will only be downloaded if the last modified date of the source URL is different from the last modified date of the file that has already been downloaded or if the file have not already been downloaded.
          
          .PARAMETER URL
          The URL where the file is located.

          .PARAMETER Destination
          The full file path where the cabinet will be downloaded to. If not specified, a default value will be used.

          .EXAMPLE
          Invoke-FileDownload -URL 'https://dl.dell.com/catalog/DriverPackCatalog.cab' -Destination "$($Env:ProgramData)\Dell\DriverPackCatalog\DriverPackCatalog.cab" -Verbose

          .EXAMPLE
          $DownloadDetails = Invoke-FileDownload -URL 'https://dl.dell.com/catalog/DriverPackCatalog.cab' -Destination "$($Env:ProgramData)\Dell\DriverPackCatalog\DriverPackCatalog.cab" -Verbose

          Write-Output -InputObject ($DownloadDetails)
          
          .EXAMPLE
          $InvokeFileDownloadParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
	          $InvokeFileDownloadParameters.URL = 'https://dl.dell.com/catalog/DriverPackCatalog.cab' -As [System.URI]
	          $InvokeFileDownloadParameters.Destination = "$($Env:ProgramData)\Dell\DriverPackCatalog\DriverPackCatalog.cab" -As [System.IO.FileInfo]
	          $InvokeFileDownloadParameters.ContinueOnError = $False
	          $InvokeFileDownloadParameters.Verbose = $True

          $InvokeFileDownloadResult = Invoke-FileDownload @InvokeFileDownloadParameters

          Write-Output -InputObject ($InvokeFileDownloadResult)
          
          .NOTES
          NEL               : {"report_to":"network-errors","max_age":3600}
          Report-To         : {"group":"network-errors","max_age":3600,"endpoints":[{"url":"https://www.dell.com/support/onlineapi/nellogger/log"}]}
          Accept-Ranges     : bytes
          Content-Type      : application/vnd.ms-cab-compressed
          ETag              : "8043933683ddd81:0"
          Last-Modified     : Tue, 11 Oct 2022 15:07:43 GMT
          Server            : Microsoft-IIS/10.0
          X-Powered-By      : ASP.NET
          x-arr-set         : arr4
          Content-Length    : 270867
          Date              : Thu, 20 Oct 2022 15:51:44 GMT
          Connection        : keep-alive
          Akamai-Request-BC : [a=23.207.199.174,b=78861523,c=g,n=US_VA_STERLING,o=20940]
          
          .LINK
          https://learn.microsoft.com/en-us/dotnet/api/system.net.webrequest?view=netframework-4.8
          
          .LINK
          https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=netframework-4.8#system-net-webclient-downloaddata(system-uri)
        #>
        
        [CmdletBinding(ConfirmImpact = 'Low', SupportsShouldProcess = $True)]
       
        Param
          (        
              [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName = $True)]
              [ValidateNotNullOrEmpty()]
              [System.URI]$URL,
                
              [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName = $True)]
              [ValidateNotNullOrEmpty()]
              [System.IO.DirectoryInfo]$Destination,

              [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName = $True)]
              [ValidateNotNullOrEmpty()]
              [ValidatePattern('^.*\.(.*)$')]
              [String]$FileName,
                                                            
              [Parameter(Mandatory=$False)]
              [Switch]$ContinueOnError        
          )
                    
        Begin
          {
              Try
                {
                    Switch ($True)
                      {
                          {([String]::IsNullOrEmpty($Destination) -eq $True) -or ([String]::IsNullOrWhiteSpace($Destination) -eq $True)}
                            {
                                [System.IO.DirectoryInfo]$Destination = "$($Env:Windir)\Temp"
                            }

                          {([String]::IsNullOrEmpty($FileName) -eq $True) -or ([String]::IsNullOrWhiteSpace($FileName) -eq $True)}
                            {
                                [String]$FileName = [System.IO.Path]::GetFileName($URL.OriginalString)
                            }
                      }

                    [System.IO.FileInfo]$DestinationPath = "$($Destination.FullName)\$($FileName)"
                    
                    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss tt'  ###Monday, January 01, 2019 @ 10:15:34 AM###
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
                    
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($CmdletName)`' is beginning. Please Wait..."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                      
                    [String[]]$AvailableScriptParameters = (Get-Command -Name ($CmdletName)).Parameters.GetEnumerator() | Where-Object {($_.Value.Name -inotin $CommonParameterList)} | ForEach-Object {"-$($_.Value.Name):$($_.Value.ParameterType.Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Available Function Parameter(s) = $($AvailableScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    [String[]]$SuppliedScriptParameters = $PSBoundParameters.GetEnumerator() | ForEach-Object {"-$($_.Key):$($_.Value.GetType().Name)"}
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Supplied Function Parameter(s) = $($SuppliedScriptParameters -Join ', ')"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($CmdletName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                    $OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $OutputObjectProperties.DownloadRequired = $False
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
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to create a web request for `"$($URL.OriginalString)`". Please Wait..." 
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                    
                    $WebRequest = [System.Net.WebRequest]::Create($URL.OriginalString)
                    
                    $WebRequestResponse = $WebRequest.GetResponse()
                    
                    $WebRequestResponseHeaders = $WebRequestResponse.Headers

                    $WebRequestHeaderProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

                    ForEach ($WebRequestResponseHeader In $WebRequestResponseHeaders.AllKeys)
                      {      
                          $WebRequestHeaderProperties."$($WebRequestResponseHeader)" = ($WebRequestResponseHeaders.GetValues($WebRequestResponseHeader))[0]  
                      }

                    $WebRequestHeaders = New-Object -TypeName 'PSObject' -Property ($WebRequestHeaderProperties)

                    $WebRequestHeaders.'Last-Modified' = (Get-Date -Date $WebRequestHeaders.'Last-Modified').ToUniversalTime()

                    $ContentLengthInMB = [System.Math]::Round(($WebRequestHeaders.'Content-Length' / 1MB), 2)

                    [ScriptBlock]$ExecuteDownload = {                                                        
                                                        $WebClient = New-Object -TypeName 'System.Net.WebClient'
                                                          $WebClient.UseDefaultCredentials = $True

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to download data stream from `"$($URL.OriginalString)`". Please Wait..."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Download Size: $($ContentLengthInMB) MegaBytes"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                                                                                                                                          
                                                        If ([System.IO.Directory]::Exists($DestinationPath.Directory.FullName) -eq $False) {$Null = [System.IO.Directory]::CreateDirectory($DestinationPath.Directory.FullName)}

                                                        $Null = Measure-Command -Expression {$Null = $WebClient.DownloadFile($URL.OriginalString, $DestinationPath.FullName)} -OutVariable 'DownloadExecutionTimespan'
            
                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - File download took $($Global:DownloadExecutionTimespan.Hours.ToString()) hour(s), $($Global:DownloadExecutionTimespan.Minutes.ToString()) minute(s), $($Global:DownloadExecutionTimespan.Seconds.ToString()) second(s), and $($Global:DownloadExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
            
                                                        [Int]$SecondsToWait = 3
                      
                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Pausing script execution for $($SecondsToWait) second(s). Please Wait..."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)
                      
                                                        $Null = Start-Sleep -Seconds ($SecondsToWait)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to update the last modified date of `"$($DestinationPath.FullName)`" to match `"$($URL.OriginalString)`". Please Wait..."
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Last Modified Date (Local): $($DestinationPath.LastWriteTimeUTC.ToString($DateTimeLogFormat))"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Last Modified Date (Source): $($WebRequestHeaders.'Last-Modified'.ToString($DateTimeLogFormat))"
                                                        Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                        $Null = (Get-Item -Path $DestinationPath.FullName -Force).LastWriteTimeUTC = $WebRequestHeaders.'Last-Modified'

                                                        Try {$Null = $WebClient.Dispose()} Catch {}
                                                    }
 
                    Switch ([System.IO.File]::Exists($DestinationPath.FullName))
                      {
                          {($_ -eq $True)}
                            {
                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Destination path `"$($DestinationPath.FullName)`" already exists."
                                Write-Verbose -Message ($LoggingDetails.LogMessage)
                                
                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to check the last modified date of `"$($DestinationPath.FullName)`" to see if a download is necessary."
                                Write-Verbose -Message ($LoggingDetails.LogMessage)
                                
                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Last Modified Date (Source): $($WebRequestHeaders.'Last-Modified'.ToString($DateTimeLogFormat))"
                                Write-Verbose -Message ($LoggingDetails.LogMessage)

                                $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Last Modified Date (Local): $($DestinationPath.LastWriteTimeUTC.ToString($DateTimeLogFormat))"
                                Write-Verbose -Message ($LoggingDetails.LogMessage)
                        
                                Switch (($DestinationPath.LastWriteTimeUTC -ine $WebRequestHeaders.'Last-Modified'))
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A redownload of `"$($URL.OriginalString)`" is necessary."
                                            Write-Warning -Message ($LoggingDetails.WarningMessage)

                                            $OutputObjectProperties.DownloadRequired = $True
                                    
                                            $ExecuteDownload.Invoke()
                                        }

                                      Default
                                        {
                                            $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A redownload of `"$($URL.OriginalString)`" is not necessary."
                                            Write-Verbose -Message ($LoggingDetails.LogMessage)
                                        }
                                  }
                            }

                          Default
                            {
                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Destination path `"$($DestinationPath.FullName)`" does not exist."
                                Write-Warning -Message ($LoggingDetails.WarningMessage)
                                
                                $LoggingDetails.WarningMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - A download of `"$($URL.OriginalString)`" is necessary."
                                Write-Warning -Message ($LoggingDetails.WarningMessage)

                                $OutputObjectProperties.DownloadRequired = $True
                        
                                $ExecuteDownload.Invoke()
                            }
                      } 
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                { 
                    Try {$Null = $WebRequestResponse.Dispose()} Catch {}
                }
          }
        
        End
          {                                        
              Try
                {
                    #Determine the date and time the function completed execution
                      $FunctionEndTime = (Get-Date)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($CmdletName) ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                      Write-Verbose -Message ($LoggingDetails.LogMessage)

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                    
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($CmdletName)`' is completed."
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
              Finally
                {      
                    $DestinationPathDetails = Get-Item -Path $DestinationPath.FullName -Force
                    
                    $OutputObjectProperties.DownloadPath = $DestinationPathDetails
                    $OutputObjectProperties.URL = $URL
                    $OutputObjectProperties.URLHeaders = $WebRequestHeaders

                    $OutputObjectProperties.CompletionTimespan = $Null

                    Switch ($True)
                      {
                          {($OutputObjectProperties.DownloadRequired -eq $True)}
                            {
                                $OutputObjectProperties.CompletionTimespan = $Global:DownloadExecutionTimespan
                            }
                      }
                      
                    $OutputObject = New-Object -TypeName 'PSObject' -Property ($OutputObjectProperties)

                    Write-Output -InputObject ($OutputObject)
                }
          }
    }
#endregion