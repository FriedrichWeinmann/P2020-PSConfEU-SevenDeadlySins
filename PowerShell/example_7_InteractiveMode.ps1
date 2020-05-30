<#
Name:       MyScript.ps1
Author:     Max Mustermann
Company:    Example Inc.
Created on: 1.2.2020
Version:    1.0.0

Creates report on all script files in the target folder
#>

$sourcePath = Read-Host -Prompt 'Specify folder to scan'
$outputPath = Read-Host -Prompt 'Specify output csv file-path for report'

Get-ChildItem -Path $sourcePath -Force | Export-Csv -Path $outputPath -NoTypeInformation