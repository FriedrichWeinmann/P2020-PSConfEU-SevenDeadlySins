$svrsizebytes = 35GB
$MemStartUp = 2048MB
$MaxMem = 2GB
$int_lab = 'lab_internal'
$Use_int_lab = 'lab_internal'
$Shosts = Get-Content $home\Desktop\Shosts.csv
$Chosts = Get-Content $home\Desktop\Chosts.csv
$VmServerVHDX = "c:\users\wwstudent\Desktop\win_server_2016.vhdx"
$vmClientVHDX = "c:\users\wwstudent\Desktop\win_10_ent.vhdx"
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
$VmCU = '.\Admin'
$VmCPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force
$VmCCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmCU,$VmCPword
$time = Get-Date
mkdir 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
mkdir 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Clients'
foreach ($hostsvm in $Shosts){
$time = Get-Date
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
$hostsvhdxpath = "$vhdxpath\$hostsvm.vhdx"
$vmpath = 'C:\ProgramData\Microsoft\Windows\Hyper-V'
Copy-Item -Path $VmServerVHDX -Destination $vhdxpath 
rename-item -Path $vhdxpath\win_server_2016.vhdx -NewName "$hostsvm.vhdx"
new-vm  -Name $hostsvm -MemoryStartupBytes $MemStartUp -SwitchName $Use_int_lab -VHDPath $hostsvhdxpath -Generation 2
set-vm -name $hostsvm -ProcessorCount 1 -MemoryMinimumBytes $memstartup -MemoryMaximumBytes $maxmem
Add-VMDvdDrive -VMName $hostsvm -Path $null
Write-Verbose "[$hostsvm] has been syspreped and shutting down at [$time]" -verbose
}
foreach ($hostsvm in $Chosts){
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Clients'
$hostsvhdxpath = "$vhdxpath\$hostsvm.vhdx"
$vmpath = 'C:\ProgramData\Microsoft\Windows\Hyper-V'
Copy-Item -Path $VmClientVHDX -Destination $vhdxpath 
rename-item -Path $vhdxpath\win_10_ent.vhdx -NewName "$hostsvm.vhdx"
new-vm  -Name $hostsvm -MemoryStartupBytes $MemStartUp -SwitchName $Use_int_lab -VHDPath $hostsvhdxpath -Generation 2
set-vm -name $hostsvm -ProcessorCount 1 -MemoryMinimumBytes $memstartup -MemoryMaximumBytes $maxmem
Add-VMDvdDrive -VMName $hostsvm -Path $null
}
$sysprep = 'C:\Windows\System32\Sysprep\sysprep.exe'
$arg = ' /oobe /generalize /shutdown /mode:vm /unattend:c:\windows\panther\autounattend.xml'
$sysprep += $arg 
invoke-expression $sysprep
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
$VmCU = '.\Admin'
$VmCPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force
$VmCCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmCU,$VmCPword
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$DomainName = 'Contoso.com'
$DomainPword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -force
$ADDSDepMod = import-module ADDSDeployment | out-null
$DisableFW = Set-NetFirewallProfile -Name Domain,Private,Public -Enabled False
$Day = Get-Date
$SetZone = set-timezone -id 'Pacific Standard Time' -PassThru
$time = Get-Date
Write-Verbose "starting the configuration of [$Con1]" -verbose
$Con1 = 'ContosoDC1'
start-vm $Con1
Write-Verbose "[$Con1] started at [$time]" -verbose
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName $Con1 -Credential $VmSCred -ScriptBlock {
Rename-Computer ContosoDC1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.10.2 -PrefixLength 24 -DefaultGateway 192.168.10.1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |Set-DnsClientServerAddress -ServerAddresses ('192.168.10.3','127.0.0.1')
$Using:DisableFW
}-AsJob | wait-job -force 
stop-vm $Con1 -AsJob | Wait-Job -Force
Write-Verbose "completed networking for [$Con1] at [$time]" -verbose
start-vm $Con1 -AsJob| Wait-Job -force
Write-Verbose "[$Con1] started at [$time] for installation of roles and congiguration of ADDS Forest" -verbose
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $Con1 -Credential $VmSCred -scriptblock {
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
import-module ADDSDeployment
$psswd = ConvertTo-SecureString -AsPlainText P@ssw0rd  -force
Install-ADDSForest -DomainName Contoso.com -InstallDns:$True -CreateDnsDelegation:$false `
 -DomainMode WinThreshold -safemodeadministratorpassword $psswd `
-ForestMode WinThreshold  -DomainNetbiosName Contoso -Force:$True `
-NoRebootOnCompletion:$true
}
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Write-Verbose "[$Con1] completed installation and configuration of ADDS Forest at [$time]" -verbose
start-vm $Con1
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $Con1 -Credential $VmDCred -scriptblock {
Write-Verbose " Initiating the intallation and configuration of DHCP on [$Con1] at [$time]" -verbose
Install-WindowsFeature -Name DHCP -IncludeManagementTools -IncludeAllSubFeature
netsh dhcp add securitygroups
add-dhcpserversecuritygroup
Restart-Service dhcpserver
Add-DHCPServerv4Scope -Name 'User Scope' -StartRange 192.168.10.10 -EndRange 192.168.10.30 `
-SubnetMask 255.255.255.0 -State Active
Set-DhcpServerv4Scope -ScopeId 192.168.10.0 -LeaseDuration 4.00:00:00
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 -DnsDomain Contoso.com -DnsServer 192.168.10.2 `
-Router 192.168.10.1
Add-DhcpServerInDC 
}-AsJob | wait-job -force
Write-Verbose "Completed the intallation and configuration of DHCP on [$Con1] at [$time]" -verbose
stop-vm $Con1 -AsJob | wait-job -Force
start-vm $Con1 -AsJob | wait-job 
Write-Verbose "waiting for [$Con1] to complete boot up" -verbose
while ((icm -VMName $con1 -Credential $vmdcred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
$ConM1 = 'ContosoMem1'
start-vm $ConM1
Write-Verbose "[$ConM1] was started at [$time]" -Verbose 
start-vm $ConM1
while ((icm -VMName $conm1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName $ConM1 -Credential $VmSCred -ScriptBlock {
Rename-Computer ContosoMem1
$Using:SetZone
set-date -date $Using:Day
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.10.4 -PrefixLength 24 -DefaultGateway 192.168.10.1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |Set-DnsClientServerAddress -ServerAddresses ('192.168.10.2','192.168.10.3')
$Using:DisableFW
shutdown -r -t 0
} -AsJob | wait-job -force 
while ((icm -VMName $conm1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $ConM1 -Credential $VmSCred -ScriptBlock {
add-computer -DomainName $using:DomainName -Credential $using:vmdcred
shutdown -r -t 0
}
while ((icm -VMName $conm1 -Credential $vmdcred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
$ConC1 = 'ContosoClient1'
Start-VM $ConC1
Invoke-Command -VMName $ConC1 -Credential $VmCCred -ScriptBlock {
Rename-Computer ContosoClient1 
$Using:SetZone
set-date -date $Using:Day
$Using:DisableFW
shutdown -r -t 0
}
while ((icm -VMName $conC1 -Credential $vmccred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName ContosoClient1 -Credential $VmCCred -ScriptBlock {
ipconfig /release
ipconfig /renew
}
Ex5 Proj: Add additional Domain Controller to an existing Forest
The creation of the vm was executed in the Ex2 Proj section
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$DomainName = 'Contoso.com'
$ADDSMod = import-module ActiveDirectory
$DisableFW = Set-NetFirewallProfile -Name Domain,Private,Public -Enabled False
$DomainPword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -force
$SetZone = set-timezone -id 'Pacific Standard Time' -PassThru
$Day = Get-Date
$Con2 = 'ContosoDC2'
Start-vm $Con2
while ((icm -VMName $Con2 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName $con2 -Credential $VmSCred -ScriptBlock {
Rename-Computer ContosoDC2
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.10.3 -PrefixLength 24 -DefaultGateway 192.168.10.1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |Set-DnsClientServerAddress -ServerAddresses ('192.168.10.2','127.0.0.1')
$Using:SetZone
set-date -date $Using:Day
$Using:DisableFW
shutdown -r -t 0
}
start-vm $Con2
while ((icm -VMName $Con2 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName $Con2 -Credential $VmSCred -ScriptBlock {
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Add-Computer -DomainName $Using:DomainName -Credential $Using:VmDCred 
$Using:ADDSMod
Install-ADDSDomainController -InstallDns -DomainName $Using:DomainName -Credential $Using:VmDCred -SafeModeAdministratorPassword ($Using:DomainPword)
} 
Ex6 Proj: Decomission a Forest and Domain, Verify Domain
This project has 2 parts
Part 1: Decomssioned domain in the order of removing systems from domain then decomission
forest from ContosoDC1 
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
$VmCU = '.\Admin'
$VmCPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force
$VmCCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmCU,$VmCPword
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$DomainName = 'Contoso.com'
$DomainPword = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDPword
$Con1 = 'ContosoDC1'
$Con2 = 'ContosoDC2'
$ConM1 = 'ContosoMem1'
$ConC1 = 'ContosoClient1'
$time = Get-Date
start-vm $ConC1 
Invoke-Command -VMName $ConC1 -Credential $VMDCred -ScriptBlock {
Remove-Computer -UnjoinDomainCredential $Using:VmDCred -LocalCredential $using:vmccred -Force
shutdown -r -t 0
}
Start-VM $ConM1
Invoke-Command -VMName $ConM1 -Credential $VmDCred -ScriptBlock {
Remove-Computer -UnjoinDomainCredential $Using:VmDCred -LocalCredential $using:vmscred -Force
shutdown -s -t 0
}
start-Vm $Con2
Invoke-Command -VMName $Con2 -Credential $VmDCred -ScriptBlock {
Import-Module ADDSDeployment
Uninstall-ADDSDomainController -ForceRemoval -SkipPreChecks -localadministratorpassword (ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) `
-norebootoncompletion:$false -force -demoteoperationmasterrole
}
start-vm $Con1
Invoke-Command -VMName $Con1 -Credential $VmDCred -ScriptBlock {
remove-dhcpserverindc
remove-windowsfeature -name DHCP
Uninstall-addsdomaincontroller -skipPreChecks -localadministratorpassword (ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force) -demoteoperationmasterrole -lastdomaincontrollerindomain:$true -norebootoncompletion:$false -force -ignorelastdcindomainmismatch
}
write-verbobse "The domain has been decomissioned on [$Con1]and the systems removed from the domain"
Part 2: Re-install the roles, rebuild and configure the AD environment. Add systems to the domain 
Write-Verbose "[$Con1] started at [$time] for installation of roles and congiguration of ADDS Forest" -verbose
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $Con1 -Credential $VmSCred -scriptblock {
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
import-module ADDSDeployment
$psswd = ConvertTo-SecureString -AsPlainText P@ssw0rd  -force
Install-ADDSForest -DomainName Contoso.com -InstallDns:$True -CreateDnsDelegation:$false `
 -DomainMode WinThreshold -safemodeadministratorpassword $psswd `
-ForestMode WinThreshold  -DomainNetbiosName Contoso -Force:$True `
-NoRebootOnCompletion:$false
}
while ((icm -VMName $con1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $Con1 -Credential $VmDCred -scriptblock {
Write-Verbose " Initiating the intallation and configuration of DHCP on [$Con1] at [$time]" -verbose
Install-WindowsFeature -Name DHCP -IncludeManagementTools -IncludeAllSubFeature
netsh dhcp add securitygroups
add-dhcpserversecuritygroup
Restart-Service dhcpserver
Add-DHCPServerv4Scope -Name 'User Scope' -StartRange 192.168.10.10 -EndRange 192.168.10.30 `
-SubnetMask 255.255.255.0 -State Active
Set-DhcpServerv4Scope -ScopeId 192.168.10.0 -LeaseDuration 4.00:00:00
Set-DhcpServerv4OptionValue -ScopeId 192.168.10.0 -DnsDomain Contoso.com -DnsServer 192.168.10.2 `
-Router 192.168.10.1
Add-DhcpServerInDC 
}-AsJob | wait-job -force
start-vm $Con2
Invoke-Command -VMName $Con2 -Credential $VmSCred -ScriptBlock {
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Add-Computer -DomainName $Using:DomainName -Credential $Using:VmDCred 
$Using:ADDSMod
Install-ADDSDomainController -InstallDns -DomainName $Using:DomainName -Credential $Using:VmDCred -SafeModeAdministratorPassword ($Using:DomainPword)
} 
start-vm $ConM1
while ((icm -VMName $conm1 -Credential $vmscred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
invoke-command -VMName $ConM1 -Credential $VmSCred -ScriptBlock {
add-computer -DomainName $using:DomainName -Credential $using:vmdcred
shutdown -r -t 0
}
start-vm $ConC1
while ((icm -VMName $conC1 -Credential $vmccred {"Test"} -ea SilentlyContinue)-ne "Test") {sleep -Seconds 1}
Invoke-Command -VMName ContosoClient1 -Credential $VmCCred -ScriptBlock {
ipconfig /release
ipconfig /renew
Add-Computer -DomainName $Using:DomainName -Credential $Using:VmDCred 
shutdown -r -t 0
}
Ex 7 Proj: Create a file share
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$Con1 = 'ContosoDC1'
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
new-vhd -Path $vhdxpath\Contoso_ShareDrive.vhdx -Fixed -SizeBytes 15GB
Add-VMHardDiskDrive -Path $vhdxpath\Contoso_ShareDrive.vhdx -VMName $con1
start-vm -vmname $Con1 
Invoke-Command -VMName $Con1 -Credential $VmDCred -ScriptBlock {
get-disk | ?{$_.OperationalStatus -eq 'offline'} | Initialize-Disk `
 | New-Partition -AssignDriveLetter -UseMaximumSize | format-volume -FileSystem NTFS -Confirm:$false -force 
$disk = get-disk | ?{$_.BootFromDisk -eq $false}
New-Volume -Disk $disk -FileSystem NTFS -DriveLetter S -FriendlyName 'Contoso_Share'
mkdir s:\Share
New-smbshare -name 'Contoso_Share' -Path s:\share -Description 'Share for the Contoso domain'
}
Ex8  Proj: Create OUs and User Objects
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$Con1 = 'ContosoDC1'
$GenPop = 'OU=GenPop,DC=Contoso,DC=Com'
$Administrators = 'OU=Administrators,DC=Contoso,DC=Com'
$DA = 'OU=Domain Administrators,OU=Administrators,DC=Contoso,DC=Com'
$U = 'OU=Users,OU=GenPop,DC=Contoso,DC=Com'
Invoke-Command -vmname $con1 -credential $vmdcred -scriptblock {
New-ADOrganizationalUnit -Name 'GenPop' -Path 'DC=contoso,DC=Com' 
New-ADOrganizationalUnit -Name 'Users' -Path $Using:GenPop
New-ADOrganizationalUnit -Name 'Computers' -Path $Using:GenPop
New-ADOrganizationalUnit -Name 'Administrators' -Path 'DC=contoso,DC=Com'
New-ADOrganizationalUnit -Name 'Domain Administrators' -Path $Using:Administrators
New-ADOrganizationalUnit -Name 'Computers' -Path $Using:Administrators
New-ADUser -Name 'Chester Cheeto DA' -GivenName 'Chester' -Surname 'Cheeto' `
-SamAccountName 'Chester.Cheeto.DA' -UserPrincipalName 'Chester.Cheeto.DA@Contoso.com' `
-Path $Using:DA -AccountPassword (ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -Force) `
-Enabled $true 
New-ADUser -Name 'Aunt Jemima DA' -GivenName 'Aunt' -Surname 'Jemima' `
-SamAccountName 'Aunt.Jemima.DA' -UserPrincipalName 'Aunt.Jemima.DA@Contoso.com' `
-Path $Using:DA -AccountPassword (ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -Force) `
-Enabled $true 
New-ADUser -Name 'Tony Tiger' -GivenName 'Tony' -Surname 'Tiger' `
-SamAccountName 'Tony.Tiger' -UserPrincipalName 'Tony.Tiger@Contoso.com' `
-Path $Using:U -AccountPassword (ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -Force) `
-Enabled $true 
New-ADUser -Name 'Captain Crunch' -GivenName 'Captain' -Surname 'Crunch' `
-SamAccountName 'Captain.Crunch' -UserPrincipalName 'Captain.Crunch@Contoso.com' `
-Path $Using:U -AccountPassword (ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -Force) `
-Enabled $true 
}
Ex9  Proj: Creating and Managing Groups
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$Con1 = 'ContosoDC1'
$DA = 'OU=Domain Administrators,OU=Administrators,DC=Contoso,DC=Com'
$U = 'OU=Users,OU=GenPop,DC=Contoso,DC=Com'
Invoke-Command -VMName $Con1 -Credential $VmDCred -ScriptBlock {
$GUs = Get-aduser -filter * -searchbase $Using:U
New-ADGroup -Name 'General Users' -SamAccountName GerenalUsers -GroupCategory Security `
-GroupScope Global -DisplayName "General Users" -Path $Using:U `
-Description "Members of this group are General Users"
Add-ADGroupMember -Identity 'General Users' -Members $GUs
$DAs =  Get-aduser -filter * -searchbase $Using:DA
Get-ADGroup -Identity 'Domain Admins'| move-adobject -targetpath $Using:DA 
}  
Ex10  Proj: Creating and Managing Groups
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$VmDCC = 'Contoso.com\Captain.Crunch'
$VmDCCPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCCCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDCC,$VmDCCPword
$ConC1 = 'ContosoClient1'
$Con1 = 'ContosoDC1'
$DomainName = 'Contoso.com'
$CompPath = 'OU=Computers,ou=genpop,dc=contoso,dc=com'
Invoke-Command -VMName $con1 -Credential $VmDCred -scriptblock{
New-ADComputer -Name ContosoClient1 -DisplayName ContosoClient1 -Path $Using:CompPath
cd ad:
$comp = get-adcomputer -filter {name -like 'ContosoClient1'}
$acl = get-acl -path ($comp.DistinguishedName)
$user = [System.Security.Principal.NTAccount]'contoso.com\Captain.Crunch'
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user,[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,[System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($ace)
set-acl $comp.DistinguishedName $acl
cd c:\
}
start-vm $ConC1
Invoke-Command -VMName $ConC1 -Credential $VmCCred -ScriptBlock {
Add-Computer -DomainName $Using:DomainName -Credential $Using:VmDCCCred -Restart
}
invoke-command -VMName $Con1 -Credential $VmDCred -ScriptBlock{
$wherecomp = get-adcomputer $using:ConC1 
$wherecomp | move-adobject -targetpath 'dc=contoso,dc=com'
$wherecomp = get-adcomputer $using:ConC1 
write-verbose "[$wherecomp]" -Verbose
$wherecomp | move-adobject -targetpath $Using:CompPath
$wherecomp = get-adcomputer $using:ConC1 
write-verbose "[$wherecomp]" -Verbose
}
Ex11  Proj: Implement ISCSI
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
$Con1 = 'ContosoDC1'
$ConM1 = 'ContosoMem1'
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
New-VMSwitch -Name 'Lab_ISCSI' -SwitchType Internal 
Get-NetIPAddress | ?{$_.InterfaceAlias -like '*Lab_ISCSI*'} | New-NetIPAddress -IPAddress 192.168.20.1 -PrefixLength 24
new-vhd -Path $vhdxpath\ISCSI_Drive.vhdx -Fixed -SizeBytes 15GB
Add-VMHardDiskDrive -Path $vhdxpath\ISCSI_Drive.vhdx -VMName $ConM1
Add-VMNetworkAdapter -VMName $Con1 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC1'
Add-VMNetworkAdapter -VMName $Con1 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC2'
Add-VMNetworkAdapter -VMName $ConM1 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC1'
Add-VMNetworkAdapter -VMName $ConM1 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC2'
Invoke-Command -VMName $ConM1 -Credential $VmDCred -ScriptBlock {
Install-WindowsFeature -Name FS-iSCSITarget-Server -IncludeAllSubFeature -IncludeManagementTools
shutdown -r -t 0
}
Invoke-Command -VMName $ConM1 -Credential $VmDCred -ScriptBlock {
get-disk | ?{$_.OperationalStatus -eq 'offline'} | Initialize-Disk `
 | New-Partition -AssignDriveLetter -UseMaximumSize | format-volume -FileSystem NTFS -Confirm:$false -force 
$disk = get-disk | ?{$_.BootFromDisk -eq $false}
New-NetIPAddress -InterfaceAlias 'Ethernet 4' -IPAddress 192.168.20.2 -PrefixLength 24 -DefaultGateway 192.168.20.1
New-NetIPAddress -InterfaceAlias 'Ethernet 5' -IPAddress 192.168.20.3 -PrefixLength 24 -DefaultGateway 192.168.20.1
get-service -Name MSiSCSI | Set-Service -StartupType Automatic
Start-Service -name msiscsi
New-Volume -Disk $disk -FileSystem NTFS -DriveLetter I -FriendlyName 'ISCSI'
mkdir I:\ISCSI
New-IscsiVirtualDisk -Path I:\ISCSI\ISCSI_D1.vhdx -SizeBytes 2GB 
New-IscsiVirtualDisk -Path I:\ISCSI\ISCSI_D2.vhdx -SizeBytes 2GB
New-IscsiServerTarget -TargetName 'Contoso-ISCSI' 
Add-IscsiVirtualDiskTargetMapping -TargetName 'Contoso-ISCSI' -Path I:\ISCSI\ISCSI_D1.vhdx
Add-IscsiVirtualDiskTargetMapping -TargetName 'Contoso-ISCSI' -Path I:\ISCSI\ISCSI_D2.vhdx 
Set-IscsiServerTarget -TargetName 'Contoso-ISCSI' -InitiatorIds ("IPAddress:192.168.20.2","IPAddress:192.168.20.3","IPAddress:192.168.20.4","IPAddress:192.168.20.5") -Enable $true
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.2 
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.3 
restart-serivce MSISCSI
Get-IscsiTarget | Connect-IscsiTarget -Ispersistent $true
}
Invoke-Command -VMName $con1 -Credential $VmDCred -ScriptBlock {
get-service -Name MSiSCSI | Set-Service -StartupType Automatic
Start-Service -name msiscsi
shutdown -r -t 0
}
Invoke-Command -VMName $Con1 -Credential $VmDCred -ScriptBlock {
New-NetIPAddress -InterfaceAlias 'Ethernet 4' -IPAddress 192.168.20.4 -PrefixLength 24 -DefaultGateway 192.168.20.1
New-NetIPAddress -InterfaceAlias 'Ethernet 5' -IPAddress 192.168.20.5 -PrefixLength 24 -DefaultGateway 192.168.20.1
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.2 
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.3 
Update-IscsiTarget
Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true
Get-IscsiVirtualDisk
get-disk | ?{$_.FriendlyName -like '*msft virtual hd*'} | Initialize-Disk `
 | New-Partition -AssignDriveLetter -UseMaximumSize | format-volume -FileSystem NTFS -Confirm:$false -force 
$iscsi1 = get-disk | ?{$_.Number -eq 2}
$iscsi2 = get-disk | ?{$_.Number -eq 3}
New-Volume -Disk $iscsi1 -FileSystem NTFS -FriendlyName 'Contoso_ISCSI_1' -DriveLetter I
New-Volume -Disk $iscsi2 -FileSystem NTFS -FriendlyName 'Contoso_ISCSI_2' -DriveLetter J
}
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
$Con1 = 'ContosoDC1'
$ConM1 = 'ContosoMem1'
$ConM2 = 'ContosoMem2'
$ConM3 = 'ContosoMem3'
$vhdxpath = 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\Servers'
$VmDU = 'Contoso.com\Administrator'
$VmDPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmDCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmDU,$VmDPword
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
$VmSU = '.\Administrator'
$VmSPword = ConvertTo-SecureString -string 'P@ssw0rd' -AsPlainText -force 
$VmSCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VmSU,$VmSPword
Invoke-Command -VMName $ConM1 -Credential $VmDCred -ScriptBlock {
Set-IscsiServerTarget -TargetName 'Contoso-ISCSI' -InitiatorIds ("IPAddress:192.168.20.2","IPAddress:192.168.20.3","IPAddress:192.168.20.4","IPAddress:192.168.20.5","IPAddress:192.168.20.6","IPAddress:192.168.20.8") -Enable $true
}
start-vm $ConM2
Invoke-Command -VMName $ConM2 -Credential $VmsCred -ScriptBlock {
Rename-Computer ContosoMem2
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.10.5 -PrefixLength 24 -DefaultGateway 192.168.10.1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |Set-DnsClientServerAddress -ServerAddresses ('192.168.10.3','192.168.10.2')
set-netfirewallprofile -name domain,private,public -Enabled False
shutdown -r -t 0
}
Add-VMNetworkAdapter -VMName $ConM2 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC1'
Add-VMNetworkAdapter -VMName $Conm2 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC2'
Invoke-Command -VMName $ConM2 -Credential $VmSCred -ScriptBlock {
Add-Computer -DomainName contoso.com -Credential $using:VmDCred -Restart
}
Invoke-Command -VMName $ConM2 -Credential $VmDCred -ScriptBlock {
Install-WindowsFeature -name FS-Fileserver -IncludeAllSubFeature -IncludeManagementTools
New-NetIPAddress -InterfaceAlias 'Ethernet 4' -IPAddress 192.168.20.6 -PrefixLength 24 -DefaultGateway 192.168.20.1
New-NetIPAddress -InterfaceAlias 'Ethernet 5' -IPAddress 192.168.20.7 -PrefixLength 24 -DefaultGateway 192.168.20.1
get-service -name ClusSvc| set-service -StartupType Automatic
Start-Service -name MSiSCSI
Set-Service -name MSiSCSI -StartupType Automatic
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.2 
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.3 
Update-IscsiTarget
Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true
get-disk|?{$_.IsOffline -eq $true}| set-disk -IsOffline $false
}
start-vm $ConM3
Invoke-Command -VMName $ConM3 -Credential $VmsCred -ScriptBlock {
Rename-Computer ContosoMem3
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |New-NetIPAddress -AddressFamily IPv4 -IPAddress 192.168.10.6 -PrefixLength 24 -DefaultGateway 192.168.10.1
Get-NetIPInterface | ?{$_.ifAlias -like 'ethernet*' -and $_.AddressFamily -eq 'ipv4'} |Set-DnsClientServerAddress -ServerAddresses ('192.168.10.3','192.168.10.2')
set-netfirewallprofile -name domain,private,public -Enabled False
shutdown -r -t 0
}
Invoke-Command -VMName $ConM3 -Credential $VmSCred -ScriptBlock {
Add-Computer -DomainName contoso.com -Credential $using:VmDCred -Restart
}
Add-VMNetworkAdapter -VMName $ConM3 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC1'
Add-VMNetworkAdapter -VMName $ConM3 -SwitchName 'Lab_ISCSI' -Name 'ISCSI_NIC2'
Invoke-Command -VMName $ConM3 -Credential $VmDCred -ScriptBlock {
Install-WindowsFeature -name FS-Fileserver -IncludeAllSubFeature -IncludeManagementTools
New-NetIPAddress -InterfaceAlias 'Ethernet 4' -IPAddress 192.168.20.8 -PrefixLength 24 -DefaultGateway 192.168.20.1
New-NetIPAddress -InterfaceAlias 'Ethernet 5' -IPAddress 192.168.20.9 -PrefixLength 24 -DefaultGateway 192.168.20.1
get-service -name ClusSvc| set-service -StartupType Automatic
Start-Service -name MSiSCSI
Set-Service -name MSiSCSI -StartupType Automatic
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.2 
New-IscsiTargetPortal -TargetPortalAddress 192.168.20.3 
Update-IscsiTarget
Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true
get-disk|?{$_.IsOffline -eq $true}| set-disk -IsOffline $false
}
Invoke-Command -VMName $Con1 -Credential $VmDCred -ScriptBlock {
New-ADOrganizationalUnit -Name Failover_Cluster -Path "ou=computers,ou=administrators,dc=contoso,dc=com"
New-ADOrganizationalUnit -Name Servers -Path "ou=administrators,dc=contoso,dc=com"
Get-ADComputer -Filter {name -like 'contosomem*'} | Move-ADObject -TargetPath 'ou=failover_cluster,ou=computers,ou=administrators,dc=contoso,dc=com'
Get-ADComputer -Filter {name -like 'contosomem1'} | Move-ADObject -TargetPath 'ou=Servers,ou=administrators,dc=contoso,dc=com'
}
get-vm | ?{$_.Name -like 'contosomem*'}| Checkpoint-VM -SnapshotName AtThisPointTheMemberServersDontHaveFAILOVERClusteringInstalled
Invoke-Command -VMName $ConM2 -Credential $VmDCred -ScriptBlock {
Install-WindowsFeature -name failover-clustering -IncludeAllSubFeature -IncludeManagementTools 
}
Restart-VM $ConM2 -Force
Invoke-Command -VMName $ConM3 -Credential $VmDCred -ScriptBlock {
Install-WindowsFeature -name failover-clustering -IncludeAllSubFeature -IncludeManagementTools 
}
Restart-VM $ConM3 -Force
Invoke-Command -VMName $ConM1 -Credential $VmDCred -ScriptBlock {
New-Cluster -Name Contoso-Cluster -Node contosomem2,contosomem3 -StaticAddress 192.168.10.7,192.168.20.10 
}