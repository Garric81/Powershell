#Demos: Configure DHCP Server with PowerShell

#region InstallDHCP
    #Install Server Role 
    Install-WindowsFeature -Name DHCP -ComputerName Server1
    
    #Review DHCPCommands
    Get-Command -Module DHCPServer -Verb Get

    Get-DhcpServerSetting -ComputerName Server1

    #Authorize DHCP server in domain
    Add-DhcpServerInDC -IPAddress 192.168.95.40 -DnsName Server1.wiredbrain.priv
        
    Get-DhcpServerInDC

    Get-DhcpServerSetting -ComputerName Server1
    
    #Add DHCP server to 
    help Add-DhcpServerSecurityGroup

    Add-DhcpServerSecurityGroup -ComputerName Server1

#endregion InstallDHCP#region DHCPInfo

#region DHCPInfo
#Demos: Gather Server Information and Working with scopes
#Review DHCP Server Info
Get-DhcpServerv4Statistics -ComputerName DC1
Get-DhcpServerv4FreeIPAddress -ComputerName DC1 -ScopeId 192.168.95.0
get-service -ComputerName DC1 -Name DHCPServer

#Gather Scope information
Get-DhcpServerv4Scope -ComputerName DC1 
Get-DhcpServerv4Scope -ComputerName DC1 -ScopeId 192.168.95.0 | format-list
Get-DhcpServerv4OptionValue -ComputerName DC1 -All |fl
Get-DhcpServerv4OptionValue -ComputerName DC1 -All -ScopeId 192.168.95.0|fl
#endregion DHCPInfo

#region DHCPScopes

##Create a DHCP scope for the 192.168.100.0 subnet w/ a range of 192.168.10.100-.200
Add-DhcpServerv4Scope `
	-Name “App/Dev Test Scope” `
	-StartRange 192.168.100.100 `
	-EndRange 192.168.100.200 `
	-SubnetMask 255.255.255.0 `
	-ComputerName Server1.wiredbrain.priv `
	-LeaseDuration 8:0:0:0 `
    -State InActive `
    -verbose
##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway)
Set-DhcpServerv4OptionValue `
	-ScopeId 192.168.100.0 `
	-ComputerName Server1.wiredbrain.priv `
	-DnsServer 192.168.95.20 `
	-DnsDomain wiredbrain.priv `
	-Router 192.168.100.254 `
    -Verbose 
Get-DHCPServerv4Scope -ComputerName Server1 -ScopeID 192.168.100.0

#Change the Range of addresses on an existing scope on DC1
Set-DhcpServerv4Scope `
    -ComputerName DC1 `
    -ScopeId 192.168.95.0 `
    -Description 'This is the production scope for the 192.16.95.0 subnet.' `
    -StartRange 192.168.95.125 `
    -EndRange 192.168.95.200 

Get-DHCPServerv4Scope -ComputerName DC1 -ScopeID 192.168.95.0

#Set DNS Servers for DHCP Server Options on DC1
Set-DhcpServerv4OptionValue `
    -DnsServer 192.168.95.20,192.168.95.40 `
    -ComputerName DC1
Get-DhcpServerv4OptionValue -ComputerName DC1|fl

#Create a Reservation for DHCP Scope
Get-DhcpServerv4Reservation -ComputerName DC1 -ScopeId 192.168.95.0
Get-DhcpServerv4Lease -ComputerName DC1 -ScopeId 192.168.95.0|
    where 'hostname' -eq 'client1.wiredbrain.priv'|
    Add-DhcpServerv4Reservation -IPAddress 192.168.95.199 -ComputerName DC1

ipconfig /release 
ipconfig /renew   
Get-NetIPAddress -InterfaceIndex 4 -AddressFamily IPv4
#endregion DHCPscopes

#region DHCPBackup
#Scenario: You need to backup up the DHCP database and perform a test restore.
Get-ChildItem -Path '\\dc1\C$\windows\system32\dhcp\backup'

#backup one-time to defined location
Backup-DhcpServer -ComputerName DC1 -Path C:\scripts\backup
get-childitem -Path \\dc1\C$\scripts\backup

#Remove Scope
Remove-DhcpServerv4Scope -ScopeId 192.168.95.0 -ComputerName DC1 -Force
Get-DhcpServerv4Scope -ComputerName DC1
Restore-DhcpServer -ComputerName DC1 -Path C:\scripts\backup -Force
Invoke-Command -ComputerName DC1 -ScriptBlock {Restart-Service -Name DHCPServer -Force}
Get-DhcpServerv4Scope -ComputerName DC1 
Get-DhcpServerv4Lease -ScopeId 192.168.95.0 -ComputerName DC1
Get-DhcpServerv4Reservation -ScopeId 192.168.95.0 -ComputerName DC1
Get-DhcpServerv4Statistics -ComputerName DC1 | fl
#endregion DHCPBackup

#region troubleshooting
    #View network adapter information via WMI
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName Client1 
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName Client1 | gm
    
    #Create variable for IP & DHCP enabled adapter
    $IPAdapter=Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName Client1 |
         Where { $_.IpEnabled -eq $true -and $_.DhcpEnabled -eq $true}
    
    $IPAdapter.ReleaseDHCPLease()
    $IPAdapter.RenewDHCPLease()
    
    $IPAdapter. #Show options in ISE

    #Command.exe legacy commands
    ipconfig /release 
    ipconfig /renew 
#endregion troubleshooting


