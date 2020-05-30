# Option 1: Argument Completer Attribute
function Get-DomainServer1 {
    [CmdletBinding()]
    param (
        [ArgumentCompleter({ Get-DomainController })]
        [string]
        $DomainController,

        [string]
        $Name = '*'
    )

    "Retrieving $Name from $DomainController"
}

# Option 2: Attached Argument Completer
function Get-DomainServer2 {
    [CmdletBinding()]
    param (
        [string]
        $DomainController,

        [string]
        $Name = '*'
    )

    "Retrieving $Name from $DomainController"
}
Register-ArgumentCompleter -CommandName Get-DomainServer2 -ParameterName DomainController -ScriptBlock {
    Get-DomainController
}

# Option 3: PSFramework Tab Completion
function Get-DomainServer3 {
    [CmdletBinding()]
    param (
        [PsfValidateSet(TabCompletion = 'MyModule.DomainController')]
        [string]
        $DomainController,

        [string]
        $Name = '*'
    )

    "Retrieving $Name from $DomainController"
}
Register-PSFTeppScriptblock -Name "MyModule.DomainController" -ScriptBlock {
    Get-DomainController
}
Register-PSFTeppArgumentCompleter -Command Get-DomainServer3 -Parameter DomainController -Name "MyModule.DomainController"
# More Info at:
# https://psframework.org/documentation/quickstart/psframework/tabcompletion.html
# https://psframework.org/documentation/documents/psframework/tab-completion.html