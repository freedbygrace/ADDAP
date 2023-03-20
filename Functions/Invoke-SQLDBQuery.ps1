## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Invoke-SQLDBQuery
Function Invoke-SQLDBQuery
    {
        <#
            .SYNOPSIS
            This function is able to execute one or more queries against an the specified Microsoft SQL database using either Windows or SQL authentication.
          
            .DESCRIPTION
            The database connection will be opened, each database query will be executed, the results will be stored, and the database connection will be closed.
           
            .PARAMETER Server
            The FQDN or IP Address of a MS SQL database server.

            .PARAMETER Instance
            A valid instance name of the desired MS SQL database server instance. (Optional)
            
            .PARAMETER Port
            A valid port number of the MS SQL database server. (Optional)

            .PARAMETER UserID
            A valid SQL authentication username (If not specified, Windows authentication will be used.)

            .PARAMETER Password
            A valid SQL authentication password (If not specified, Windows authentication will be used.)

            .PARAMETER Database
            A valid database name that resides on the specified MS SQL database server.

            .PARAMETER DBQueryList
            One or more valid SQL queries for the specified database.
    
            .EXAMPLE
            $DBQueryResults = Invoke-SQLDBQuery -Server 'MyDBServer.mydomain.com' -UserID 'SQLAuthUser' -Password 'SQLAuthUserPassword' -Database 'YourDatabaseName' -DBQueryList @('Select * From YourTableName') -Verbose

            Write-Output -InputObject ($DBQueryResults)
            
            .EXAMPLE
            $DBQueryList = New-Object -TypeName 'System.Collections.Generic.List[String]'
              $DBQueryList.Add(@"
Select Distinct
    dbo.v_Add_Remove_Programs.DisplayName0 As 'DisplayName'
From
    dbo.v_Add_Remove_Programs
Order By
    dbo.v_Add_Remove_Programs.DisplayName0
"@)

            $DBQueryResults = Invoke-SQLDBQuery -Server 'MyDBServer.mydomain.com' -Database 'YourDatabaseName' -DBQueryList ($DBQueryList) -Verbose

            .EXAMPLE
            $DBQueryResults = Invoke-SQLDBQuery -Server 'MyDBServer.mydomain.com' -Instance 'MyDBInstance' -Database 'YourDatabaseName' -DBQueryList @('Select * From YourTableName')

            Write-Output -InputObject ($DBQueryResults)

            .EXAMPLE
            $DBQueryResults = Invoke-SQLDBQuery -Server 'MyDBServer.mydomain.com' -Port '4530' -Database 'YourDatabaseName' -DBQueryList @('Select * From YourTableName1', 'Select * From YourTableName2')

            Write-Output -InputObject ($DBQueryResults)

            .EXAMPLE
            $InvokeSQLDBQueryParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
	            $InvokeSQLDBQueryParameters.Server = "MyDBServer.mydomain.com"
	            $InvokeSQLDBQueryParameters.Instance = "MyDBInstance"
	            $InvokeSQLDBQueryParameters.Port = "1433"
	            $InvokeSQLDBQueryParameters.UserID = "sa"
	            $InvokeSQLDBQueryParameters.Password = "Password1"
	            $InvokeSQLDBQueryParameters.Database = "YourDatabaseName"
	            $InvokeSQLDBQueryParameters.DBQueryList = New-Object -TypeName 'System.Collections.Generic.List[String]'
		            $InvokeSQLDBQueryParameters.DBQueryList.Add('Select * From YourTableName1')
                $InvokeSQLDBQueryParameters.DBQueryList.Add('Select * From YourTableName2')
	            $InvokeSQLDBQueryParameters.ExportJSON = $True
	            $InvokeSQLDBQueryParameters.ExportDirectory = "$($Env:Public)\Desktop\SQLDBQueryResults"
	            $InvokeSQLDBQueryParameters.ContinueOnError = $True
	            $InvokeSQLDBQueryParameters.Verbose = $True

            $InvokeSQLDBQueryResult = Invoke-SQLDBQuery @InvokeSQLDBQueryParameters

            Write-Output -InputObject ($InvokeSQLDBQueryResult)
                    
            .LINK
            https://www.SQLshack.com/connecting-powershell-to-SQL-server/

            .LINK
            https://stackoverflow.com/questions/64681003/fetch-a-whole-row-from-SQL-server-with-powershell
        #>
        
        [CmdletBinding(ConfirmImpact = 'Low', HelpURI = '', DefaultParameterSetName = '_AllParameterSets', SupportsShouldProcess = $True)]       
          Param
            (        	     
                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [String]$Server,

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$Instance,

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$Port,
       
                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$UserID,

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$Password,

                [Parameter(Mandatory=$False)]
                [ValidateNotNullOrEmpty()]
                [String]$Database,
        
                [Parameter(Mandatory=$True)]
                [ValidateNotNullOrEmpty()]
                [String[]]$DBQueryList,

                [Parameter(Mandatory=$False, ParameterSetName = 'Export')]
                [Switch]$ExportJSON,

                [Parameter(Mandatory=$False, ParameterSetName = 'Export')]
                [System.IO.DirectoryInfo]$ExportDirectory,

                [Parameter(Mandatory=$False)]
                [Switch]$ContinueOnError  
            )
                    
        Begin
          {
              [ScriptBlock]$ErrorHandlingDefinition = {
                                                          If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                                                          [String]$ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]"

                                                          If ($ContinueOnError.IsPresent -eq $True)
                                                            {
                                                                Write-Warning -Message ($ErrorMessage)
                                                            }
                                                          ElseIf ($ContinueOnError.IsPresent -eq $False)
                                                            {
                                                                Throw ($ErrorMessage)
                                                            }
                                                      }
              
              Try
                {
                    $DateTimeMessageFormat = 'MM/dd/yyyy HH:mm:ss.FFF'  ###03/23/2022 11:12:48.347###
                    [ScriptBlock]$GetCurrentDateTimeMessageFormat = {(Get-Date).ToString($DateTimeMessageFormat)}
                    $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss.FFF tt'  ###Monday, January 01, 2019 @ 10:15:34.000 AM###
                    [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
                    $DateFileFormat = 'yyyyMMdd'  ###20190403###
                    [ScriptBlock]$GetCurrentDateFileFormat = {(Get-Date).ToString($DateFileFormat)}
                    $DateTimeFileFormat = 'yyyyMMdd_HHmmss'  ###20190403_115354###
                    [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
                    $TextInfo = (Get-Culture).TextInfo
                    
                    #Determine the date and time we executed the function
                      $FunctionStartTime = (Get-Date)
                    
                    [String]$CmdletName = $MyInvocation.MyCommand.Name 
                    
                    $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($CmdletName)`' is beginning. Please Wait..."
                    Write-Verbose -Message $LogMessage
              
                    #Define Default Action Preferences
                      $ErrorActionPreference = 'Stop'
                     
                    $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($CmdletName) began on $($FunctionStartTime.ToString($DateTimeLogFormat))"
                    Write-Verbose -Message $LogMessage
                                        
                    #Create an array list that will contain the functions output
                      $OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'

                    #Define Variable(s)
                      $LoggingDetails = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                        $LoggingDetails.Add('LogMessage', $Null)
                        $LoggingDetails.Add('WarningMessage', $Null)
                        $LoggingDetails.Add('ErrorMessage', $Null)

                    #Create a database connection string builder
                      $DBConnectionStringBuilder = New-Object -TypeName 'System.Data.SQLClient.SQLConnectionStringBuilder'

                    #Create a database data source builder
                      $DataSourceBuilder = New-Object -TypeName 'System.Text.StringBuilder'

                    #Dynamically build the connection string based on parameter values
                      Switch ($True)
                        {                
                            {([String]::IsNullOrEmpty($Server) -eq $False) -and ([String]::IsNullOrWhiteSpace($Server) -eq $False)}
                              {
                                  $Null = $DataSourceBuilder.Append($Server)
                              }

                            {([String]::IsNullOrEmpty($Instance) -eq $False) -and ([String]::IsNullOrWhiteSpace($Instance) -eq $False)}
                              {
                                  $Null = $DataSourceBuilder.Append("\$($Instance)")
                              }

                            {([String]::IsNullOrEmpty($Port) -eq $False) -and ([String]::IsNullOrWhiteSpace($Port) -eq $False)}
                              {
                                  $Null = $DataSourceBuilder.Append(",$($Port)")
                              }

                            {([String]::IsNullOrEmpty($Database) -eq $False) -and ([String]::IsNullOrWhiteSpace($Database) -eq $False)}
                              {
                                  $DBConnectionStringBuilder.PSBase.InitialCatalog = $Database
                              }

                            {([String]::IsNullOrEmpty($ExportDirectory) -eq $True) -and ([String]::IsNullOrWhiteSpace($ExportDirectory) -eq $True)}
                              {
                                  [System.IO.DirectoryInfo]$ExportDirectory = "$($Env:Public)\Documents\Reports\$($CmdletName)"
                              }   
                        }

                    $DBConnection = New-Object -TypeName 'System.Data.SQLClient.SQLConnection'
        
                    Switch ((([String]::IsNullOrEmpty($UserID) -eq $False) -and ([String]::IsNullOrWhiteSpace($UserID) -eq $False)) -and (([String]::IsNullOrEmpty($Password) -eq $False) -or ([String]::IsNullOrWhiteSpace($Password) -eq $False)))
                      {
                          {($_ -eq $True)}
                            {
                                $DBConnectionStringBuilder.PSBase.IntegratedSecurity = $False
          
                                $CredentialParameters = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                  $CredentialParameters.Add($UserID)
                                  $CredentialParameters.Add((ConvertTo-SecureString -String $Password -AsPlainText -Force))
                                
                                $Credential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList ($CredentialParameters.ToArray())

                                $Null = $Credential.Password.MakeReadOnly()
          
                                $DBConnectionCredentialParameters = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                                  $DBConnectionCredentialParameters.Add($Credential.UserName)
                                  $DBConnectionCredentialParameters.Add($Credential.Password)
                                
                                $DBConnectionCredential = New-Object -TypeName 'System.Data.SQLClient.SQLCredential' -ArgumentList ($DBConnectionCredentialParameters.ToArray())
                  
                                $DBConnection.Credential = ($DBConnectionCredential)    
                            }
                            
                          Default
                            {
                                $DBConnectionStringBuilder.PSBase.IntegratedSecurity = $True
                            }
                      }

                    $DBConnectionStringBuilder.PSBase.DataSource = $DataSourceBuilder.ToString()
        
                    $DBConnectionString = $DBConnectionStringBuilder.ConnectionString
                  
                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Database Connection String = $($DBConnectionString)"
                    Write-Verbose -Message ($LoggingDetails.LogMessage)
               
                    $DBConnection.ConnectionString = ($DBConnectionString)

                    $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to open the database connection. Please Wait..."
                    Write-Verbose -Message $LogMessage

                    $DBConnection.Open()
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
          }

        Process
          {           
              For ($DBQueryListIndex = 0; $DBQueryListIndex -lt $DBQueryList.Count; $DBQueryListIndex++)
                {
                    Try
                      {  
                          [String]$DBQuery = $DBQueryList[$DBQueryListIndex]
                          [Int]$DBQueryNumber = $DBQueryListIndex + 1
                          
                          $DBCommand = New-Object -TypeName 'System.Data.SQLClient.SQLCommand'
                            $DBCommand.Connection = ($DBConnection)
                            $DBCommand.CommandText = ($DBQuery)

                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Attempting to execute database query #$($DBQueryNumber). Please Wait..."
                          Write-Verbose -Message ($LoggingDetails.LogMessage)
        
                          $Null = $DBCommand.ExecuteScalar()
      
                          $DBQueryResults = New-Object -TypeName 'System.Data.DataTable'

                          $DBDataAdapterParameters = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                            $DBDataAdapterParameters.Add($DBCommand)
      
                          $DBDataAdapter = New-Object -TypeName 'System.Data.SQLClient.SQLDataAdapter' -ArgumentList ($DBDataAdapterParameters.ToArray())
                            
                          $Null = $DBDataAdapter.Fill($DBQueryResults)

                          $DBQueryRowCount = $DBQueryResults.Rows.Count

                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "$($DBQueryRowCount) row(s) were returned from the database query."
                          Write-Verbose -Message ($LoggingDetails.LogMessage)

                          Switch ($DBQueryRowCount -gt 0)
                            {
                                {($_ -eq $True)}
                                  {          
                                      $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Database Query Column Names = $($DBQueryResults.Columns.ColumnName -Join ', ')"
                                      Write-Verbose -Message ($LoggingDetails.LogMessage)
                                  }
                            }

                          [String]$ResultSetNumber = ($DBQueryNumber).ToString('000')
                          [String]$ResultSetPropertyName = "ResultSet$($ResultSetNumber)"

                          $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Attempting to add the result(s) from database query #$($DBQueryNumber) to property `"$($ResultSetPropertyName)`". Please Wait..."
                          Write-Verbose -Message ($LoggingDetails.LogMessage)

                          $PropertyInclusionList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                            $Null = $PropertyInclusionList.Add('*')
                          
                          $PropertyExclusionList = New-Object -TypeName 'System.Collections.Generic.List[Object]'
                            $Null = $PropertyExclusionList.AddRange(('HasErrors', 'ItemArray', 'RowError', 'RowState', 'Table'))

                          $DBQueryRows = $DBQueryResults.Rows | Select-Object -Property ($PropertyInclusionList) -ExcludeProperty ($PropertyExclusionList)

                          $Null = $OutputObjectProperties.Add($ResultSetPropertyName, $DBQueryRows)
                      }
                    Catch
                      {
                          $ErrorHandlingDefinition.Invoke()
                      }
                    Finally
                      {          
                          Try
                            {
                                $Null = $DBQueryResults.Dispose()
                                $Null = $DBDataAdapter.Dispose()
                            }
                          Catch
                            {
                            
                            }
                      }
                }    
          }
        
        End
          {                                        
              Try
                {
                    #Close the database connection
                      $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Attempting to close the database connection. Please Wait..."
                      Write-Verbose -Message $LogMessage

                      $Null = $DBConnection.Close()
                    
                    #Create the powershell object that will be exported to the powershell pipeline
                      $OutputObject = New-Object -TypeName 'PSObject' -Property ($OutputObjectProperties)

                    #If specified, export each result set to a separate JSON file
                      Switch ($True)
                        {
                            {($ExportJSON.IsPresent)}
                              {
                                  $ExportParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $ExportParameters.Add('Compress', $True)
                                    $ExportParameters.Add('Encoding', [System.Text.Encoding]::Default)
                                    $ExportParameters.Add('Depth', 10)
                                  
                                  [String[]]$OutputObjectPropertyList = $OutputObject.PSObject.Properties.Name

                                  For ($OutputObjectPropertyListIndex = 0; $OutputObjectPropertyListIndex -lt $OutputObjectPropertyList.Count; $OutputObjectPropertyListIndex++)
                                    {
                                        [String]$OutputObjectPropertyName = $OutputObjectPropertyList[$OutputObjectPropertyListIndex]

                                        [System.IO.FileInfo]$OutputObjectExportPath = "$($ExportDirectory.FullName)\$($OutputObjectPropertyName).json"

                                        Switch ([System.IO.File]::Exists($OutputObjectExportPath.FullName))
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    [String]$JSONContents = [System.IO.File]::ReadAllText($OutputObjectExportPath.FullName, $ExportParameters.Encoding)

                                                    $JSONObject = ConvertFrom-JSON -InputObject ($JSONContents)

                                                    $OutputObjectPropertyValue = $OutputObject.$($OutputObjectPropertyName)

                                                    $JSONObject.$($OutputObjectPropertyName) = ($OutputObjectPropertyValue)

                                                    [String]$OutputObjectPropertyValueAsJSON = $JSONObject | ConvertTo-JSON -Depth ($ExportParameters.Depth) -Compress:($ExportParameters.Compress)

                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Attempting to update the result set `"$($OutputObjectPropertyName)`" within the file of `"$($OutputObjectExportPath.FullName)`". Please Wait..."
                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)
                                                    
                                                    $Null = [System.IO.File]::WriteAllText($OutputObjectExportPath.FullName, $OutputObjectPropertyValueAsJSON, $ExportParameters.Encoding)
                                                }
                            
                                              {($_ -eq $False)}
                                                {
                                                    $OutputObjectPropertyValue = $OutputObject | Select-Object -Property @($OutputObjectPropertyName)
                                                    
                                                    [String]$OutputObjectPropertyValueAsJSON = $OutputObjectPropertyValue | ConvertTo-JSON -Depth ($ExportParameters.Depth) -Compress:($ExportParameters.Compress)
                                                    
                                                    Switch ([System.IO.Directory]::Exists($OutputObjectExportPath.Directory.FullName))
                                                      {
                                                          {($_ -eq $False)}
                                                            {
                                                                $Null = [System.IO.Directory]::CreateDirectory($OutputObjectExportPath.Directory.FullName)
                                                            }
                                                      }
                                                    
                                                    $LoggingDetails.LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - " + "Attempting to export the result set `"$($OutputObjectPropertyName)`" to the file of `"$($OutputObjectExportPath.FullName)`". Please Wait..."
                                                    Write-Verbose -Message ($LoggingDetails.LogMessage)

                                                    $Null = [System.IO.File]::WriteAllText($OutputObjectExportPath.FullName, $OutputObjectPropertyValueAsJSON, $ExportParameters.Encoding)
                                                }
                                          }
                                    }
                              }
                        }
                    
                    #Write the object to the powershell pipeline 
                      Write-Output -InputObject ($OutputObject)
                
                    #Determine the date and time the function completed execution
                      $FunctionEndTime = (Get-Date)

                      $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Execution of $($CmdletName) ended on $($FunctionEndTime.ToString($DateTimeLogFormat))"
                      Write-Verbose -Message $LogMessage

                    #Log the total script execution time  
                      $FunctionExecutionTimespan = New-TimeSpan -Start ($FunctionStartTime) -End ($FunctionEndTime)

                      $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function execution took $($FunctionExecutionTimespan.Hours.ToString()) hour(s), $($FunctionExecutionTimespan.Minutes.ToString()) minute(s), $($FunctionExecutionTimespan.Seconds.ToString()) second(s), and $($FunctionExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                      Write-Verbose -Message $LogMessage
                    
                    $LogMessage = "$($GetCurrentDateTimeMessageFormat.Invoke()) - Function `'$($CmdletName)`' is completed."
                    Write-Verbose -Message $LogMessage
                }
              Catch
                {
                    $ErrorHandlingDefinition.Invoke()
                }
          }
    }
#endregion