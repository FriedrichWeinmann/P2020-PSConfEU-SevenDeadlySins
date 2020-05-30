function Get-DomainServers {
    [CmdletBinding()]
    param (
        [string]
        $Name = '*'
    )

    DynamicParam {
        $runtimeParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        $parameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $parameterAttribute.Mandatory = $true
        $parameterAttribute.ParameterSetName = '__AllParameterSets'

        # This is where we gather the data
        $values = Get-DomainController
        $validateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($values)

        $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($parameterAttribute)
        $attributeCollection.Add($validateSetAttribute)

        $runtimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter(
            'DomainController',
            [string],
            $attributeCollection
        )
        $runtimeParamDictionary.Add('DomainController', $runtimeParameter)
        return $runtimeParamDictionary
    }

    begin {
        $DomainController = $PSBoundParameters.DomainController
    }
    process {
        Write-Host "Sold my Soul to retrieve $Name from $DomainController"
    }
}