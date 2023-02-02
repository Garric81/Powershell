#Create a CIM Session for remoting to server
help about_cimsession

#Create Variable for cimsession
$cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.95.100

#get IP Configuration on Remote Machine
Get-NetIPConfiguration -CimSession $cimsession

#set IP Configuration on remote system
New-netIPAddress `
-CimSession $cimsession `
-IPAddress 192.168.95.40 `
-PrefixLength 24 `
-DefaultGateway 192.168.95.2 `
-InterfaceIndex 12

Get-NetIPConfiguration -CimSession $cimsession

#Reconnect

$cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.95.40

Get-NetIPConfiguration -CimSession $cimsession

Set-DnsClientServerAddress `
-CimSession $cimsession `
-InterfaceIndex 12 `
-ServerAddresses 192.168.95.20

#Rename Server to Server1
Enter-PSSession -ComputerName 192.168.95.40 -Credential (get-credential)
    #Rename-Computer -NewName Server1
    #Set Time Zone
    #Tzutilexe /?
    #Tzutilexe /g
    #Tzutil.exe /s "Central Standard Time"
    #Restart-computer 

#Domain Join Server1
$cred = Get-Credential
Invoke-command `
-ComputerName 192.168.95.40 `
-Credential (Get-Credential) `
-scriptblock {Add-Computer -DomainName wiredbrain.priv -credential $using:cred -Restart}

#Re-Set Trusted Hosts

Get-Item WSMan:\localhost\Client\TrustedHosts

Set-item WSMAN:\Localhost\Client\TrustedHosts -value ''









