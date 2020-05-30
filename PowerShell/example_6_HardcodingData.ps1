<#
# Additional comments
#>

 #----------------------------------------------------------------------------# 
 #                                 Parameters                                 # 
 #----------------------------------------------------------------------------# 

$Path = 'F:\temp\demo'

$MaxDays = 7
 
 #----------------------------------------------------------------------------# 
 #                             Stop editing here                              # 
 #----------------------------------------------------------------------------# 
 
$limit = (Get-Date).AddDays((-1 * $MaxDays))
Get-ChildItem -Path $Path |
    Where-Object LastWriteTime -lt $limit |
        Remove-Item -Force -Recurse