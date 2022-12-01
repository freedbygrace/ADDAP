## Microsoft Function Naming Convention: http://msdn.microsoft.com/en-us/library/ms714428(v=vs.85).aspx

#region Function Convert-FileSize
Function Convert-FileSize
  {
		<#
		  .SYSNOPSIS
		  Converts a size in bytes to its upper most value.

		  .PARAMETER Size
		  The size in bytes to convert

		  .EXAMPLE
		  $ConvertFileSizeParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
			  $ConvertFileSizeParameters.Size = 4294964
			  $ConvertFileSizeParameters.DecimalPlaces = 2

		  $ConvertFileSizeResult = Convert-FileSize @ConvertFileSizeParameters

		  Write-Output -InputObject ($ConvertFileSizeResult)

		  .EXAMPLE
		  $ConvertFileSizeResult = Convert-FileSize -Size 4294964

		  Write-Output -InputObject ($ConvertFileSizeResult)

		  .NOTES
		  Size              : 429496456565656
		  DecimalPlaces     : 0
		  Divisor           : 1099511627776
		  SizeUnit          : TB
		  SizeUnitAlias     : Terabytes
		  CalculatedSize    : 391
		  CalculatedSizeStr : 391 TB
		#>

	  [CmdletBinding()]
		Param
		  (
			  [Parameter(Mandatory=$True)]
			  [ValidateNotNullOrEmpty()]
			  [Alias("Length")]
			  $Size,

			  [Parameter(Mandatory=$False)]
			  [ValidateNotNullOrEmpty()]
			  [Alias("DP")]
			  [Int]$DecimalPlaces
		  )

	  Try
		{
			Switch ($True)
			  {
				  {([String]::IsNullOrEmpty($DecimalPlaces) -eq $True) -or ([String]::IsNullOrWhiteSpace($DecimalPlaces) -eq $True)}
					{
						[Int]$DecimalPlaces = 2
					}
			  }

			$OutputObjectProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
			  $OutputObjectProperties.Size = $Size
			  $OutputObjectProperties.DecimalPlaces = $DecimalPlaces

			Switch ($Size)
			  {
				  {($_ -lt 1MB)}
					{  
						$OutputObjectProperties.Divisor = 1KB   
						$OutputObjectProperties.SizeUnit = 'KB'
						$OutputObjectProperties.SizeUnitAlias = 'Kilobytes'

						Break
					}

				  {($_ -lt 1GB)}
					{
						$OutputObjectProperties.Divisor = 1MB  
						$OutputObjectProperties.SizeUnit = 'MB'
						$OutputObjectProperties.SizeUnitAlias = 'Megabytes'

						Break
					}

				  {($_ -lt 1TB)}
					{
						$OutputObjectProperties.Divisor = 1GB   
						$OutputObjectProperties.SizeUnit = 'GB'
						$OutputObjectProperties.SizeUnitAlias = 'Gigabytes'

						Break
					}

				  {($_ -ge 1TB)}
					{
						$OutputObjectProperties.Divisor = 1TB
						$OutputObjectProperties.SizeUnit = 'TB'
						$OutputObjectProperties.SizeUnitAlias = 'Terabytes'

						Break
					}
			  }

			$OutputObjectProperties.CalculatedSize = [System.Math]::Round(($Size / $OutputObjectProperties.Divisor), $OutputObjectProperties.DecimalPlaces)
			$OutputObjectProperties.CalculatedSizeStr = "$($OutputObjectProperties.CalculatedSize) $($OutputObjectProperties.SizeUnit)"
		}
	  Catch
		{
			Write-Error -Exception $_
		}
	  Finally
		{
			$OutputObject = New-Object -TypeName 'PSObject' -Property ($OutputObjectProperties)

			Write-Output -InputObject ($OutputObject)
		}
  }
#endregion