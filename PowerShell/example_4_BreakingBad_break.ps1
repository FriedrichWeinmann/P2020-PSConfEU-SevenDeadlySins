function Get-Test {
    [CmdletBinding()]
    param ()

    Write-Host "Starting up"
    break
    Write-Host "This should never show"
}

function Get-Test2 {
    [CmdletBinding()]
    param ()

    Write-Host "Before"
    Get-Test
    Write-Host "After"
}