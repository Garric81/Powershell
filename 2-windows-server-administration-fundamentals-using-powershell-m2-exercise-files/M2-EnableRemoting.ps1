#Review help for Enable-PSRemoting on administrative workstation
help Enable-PSRemoting

#View Help file for Enable-PSSession
help Enter-PSSession

help Enter-PSSession -Examples

help Invoke-Command

help Invoke-Command -Examples

##Find DHCP Lease on DHCP Server
Get-DhcpServerv4Lease -ComputerName DC1 -AllLeases -ScopeId 192.168.95.0

Enter-PSSession -ComputerName 192.168.95.100 #Will Fail

#Set Trusted Hosts

Get-Item WSMan:\localhost\Client\TrustedHosts

Set-item WSMAN:\Localhost\Client\TrustedHosts -value *

Enter-PSSession -ComputerName 192.168.95.100 -Credential (get-credential) #WillWork
    #EnterHostname
    #Enter Exit



