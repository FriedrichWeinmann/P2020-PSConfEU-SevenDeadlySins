function Get-OSInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [PSFComputer[]]
        $ComputerName = 'localhost'
    )

    process {
        foreach ($name in $ComputerName) {
            if ($name.IsLocalhost) { $osInfo = Get-CimInstance -ClassName win32_OperatingSystem }
            else { $osInfo = Get-CimInstance -ComputerName $name -ClassName win32_OperatingSystem }
            [PSCustomObject]@{
                Computer = $osInfo.CSName
                Title    = $osInfo.Caption
                Status   = $osInfo.Status
                Version  = $osInfo.Version
            }
        }
    }
}

function Test-Script {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string[]]
        $Path
    )

    process {
        foreach ($pathString in $Path) {
            Write-Output "Testing $pathString"
            if ((Read-PSMDScript -Path $pathString).Errors) { $false }
            else { $true }
        }
    }
}

if (Test-Script 'F:\Code\Github\P2020-PSConfEU-SevenDeadlySins\PowerShell\example_3_KillingPuppies_edited.ps1') { "Is Correct" }
if (Test-Script C:\Windows\explorer.exe) { "Is Correct" }