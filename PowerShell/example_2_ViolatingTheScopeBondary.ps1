$users = 'Max','Miu','Yusuf'
$Nachname = 'Mustermann'

function Get-Test {
    [CmdletBinding()]
    param ()

    foreach ($name in $users) {
        Write-Host "Hello $name $Nachname"
    }
}

Get-Test