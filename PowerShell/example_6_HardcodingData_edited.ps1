<#
# Additional comments
#>

 #----------------------------------------------------------------------------# 
 #                                 Parameters                                 # 
 #----------------------------------------------------------------------------# 

[CmdletBinding()]
param (
    $Path = 'C:\temp\demo',

    $MaxDays = 7
)
 
 #----------------------------------------------------------------------------# 
 #                             Stop editing here                              # 
 #----------------------------------------------------------------------------# 

Write-Verbose "Logrotating $Path for files older than $MaxDays days"
$limit = (Get-Date).AddDays((-1 * $MaxDays))
Get-ChildItem -Path $Path |
    Where-Object LastWriteTime -lt $limit |
        Remove-Item -Force -Recurse