###Module 2 Demo###

##Before We begin, we need the Remote Server Adminstration Tools
## Download from https://www.microsoft.com/en-us/download/details.aspx?id=45520
Get-command -Module DHCPServer

C:\demos\WindowsTH-RSAT_TP5-x64.msu

Get-command -Module DHCPServer

Update-help -Force

##Find DHCP Lease on DHCP Server
Get-DhcpServerv4Lease -ComputerName DC1 -AllLeases



##Filter result to grab Name & IP Address


##Remote to Computer
help Enter-PSSession 

Help Enter-PSSession -Examples

Enter-PSSession -ComputerName Localhost

Enable-PSRemoting

Enter-PSSession -ComputerName Localhost

##
$env:COMPUTERNAME

Rename-Computer -NewName S1

#Install DHCP Role
Get-WindowsFeature

Add-WindowsFeature -Name DNS

##Modify Firewall Rules

gcm *firewall*

Get-NetFirewallRule|Format-Table -Property DisplayName,Enabled,Profile,DisplayGroup -Wrap

Get-NetFirewallRule *iscsi*|format-list -Property DisplayName,Enabled,Profile,DisplayGroup

Get-NetFirewallRule *iscsi* | Where-Object Profile -EQ 'Domain'|Format-Table

Get-NetFirewallRule *iscsi* | Where-Object Profile -EQ 'Domain'|disable-NetFirewallRule
