function Get-Test {
    [CmdletBinding()]
    param ()

    Write-Host "Starting up"
    throw "Something broke"
    Write-Host "This should never show"
}

function Get-Test2 {
    [CmdletBinding()]
    param ()

    Write-Host "Before"
    try { Get-Test }
    catch { "It broke" }
    Write-Host "After"
}