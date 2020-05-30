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
            Write-Host "Computer: $($osInfo.CSName)"
            Write-Host "Title:    $($osInfo.Caption)"
            Write-Host "Status:   $($osInfo.Status)"
            Write-Host "Version:  $($osInfo.Version)"
            Write-Host " "
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