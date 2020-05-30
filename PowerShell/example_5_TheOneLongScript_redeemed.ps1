<#
.SYNOPSIS
    Script that does something

.DESCRIPTION
    Script that really does something awesome.
    You need ...

    <Add more text here>

.EXAMPLE
    <Add example here>
#>
[CmdletBinding()]
param (

)

#region Statics

#endregion Statics

#region Functions
function Get-ManagementAccount {
    [CmdletBinding()]
    param ()
}
function Test-MgmtMailboxPolicy {
    [CmdletBinding()]
    param (
        $Account
    )
}

function Set-MgmtMailboxPolicy {
    [CmdletBinding()]
    param (
        $Account
    )
}

function Start-MgmtComplianceExport {
    [CmdletBinding()]
    param (
        $Account
    )
}

function Send-ComplianceReport {
    [CmdletBinding()]
    param (
        $Account
    )
}
#endregion Functions

#region Business Logic
$managementAccounts = Get-ManagementAccount
foreach ($managementAccount in $managementAccounts) {
    if (-not (Test-MgmtMailboxPolicy -Account $managementAccount)) {
        Set-MgmtMailboxPolicy -Account $managementAccount
    }

    Start-MgmtComplianceExport -Account $managementAccount
}
Send-ComplianceReport -Account $managementAccounts
#endregion Business Logic