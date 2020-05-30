$users = 'Max','Miu','Yusuf'
$Nachname = 'Mustermann'

function Get-Test {
    [CmdletBinding()]
    param (
        $Users,

        $Nachname
    )

    foreach ($name in $Users) {
        Write-Host "Hello $name $Nachname"
    }
}

Get-Test -Users $users -Nachname $Nachname