  ##Demos: Configuring DNS with PowerShell

  #region Demo1-Querying
  
    #Test Network Connectivity and Name Resolution in one step
        Test-NetConnection -ComputerName pluralsight.com 
    
    #querying DNS
        Resolve-DnsName -Type ALL -Name pluralsight.com -Server 4.2.2.1 

        Resolve-DnsName -Name wiredbrain.priv -Type A -Server DC1.wiredbrain.priv

        Resolve-DnsName -Name wiredbrain.priv -Type A -Server Server1.wiredbrain.priv

        Resolve-DnsName -Name pluralsight.com -Type MX -Server DC1.wiredbrain.Priv
    
    #DNS Client Stuff
        Get-DnsClientCache                                                                                               
	    gcm *DNSClient*                                                                                                   
	    Clear-DNSClientCache                                                                                              
	    Get-DnsClientCache                                                                                                
        Get-DnsClientServerAddress -CimSession (New-CimSession -ComputerName DC1)
    


    #configure DNS Server Settings
        Get-DnsServer -ComputerName DC1 |gm
        
        get-dnsserver -ComputerName DC1

        Get-DnsServerSetting -All -ComputerName DC1

        Get-DNSServerSetting -ComputerName DC1 -all | select RoundRobin

        Get-DnsServerSetting -computername DC1 -all | Export-Clixml  C:\Demos\testdns.xml
        
        notepad c:\demos\testdns.xml
        
        Import-Clixml C:\demos\testdns-u.xml | Set-DnsServerSetting -ComputerName DC1 
        
        Get-DNSServerSetting -ComputerName DC1 -all | select RoundRobin

    #Configure with WMI
        $Server = Get-WMIObject MicrosoftDNS_Server `
                    -Namespace "root\MicrosoftDNS" `
                    -Computer DC1
        $Server
        
        $Server | Get-Member
        
        # Setting RoundRobin
        $Server.RoundRobin = 'false'
        
        $Server.Put()
        
        # Start Scavenging
        $Server.RoundRobin

  #endregion demo1-querying

  #region Demo2:forwaders
      #configure Forwarders
          Get-DnsServerForwarder -ComputerName DC1 
          Get-DnsServerForwarder -ComputerName Server1
          
      #Standard Forwarders
          Resolve-DnsName -Name dc1.wiredbrain.priv -Server Server1.wiredbrain.priv
          Add-DnsServerForwarder -IPAddress 192.168.95.20 -ComputerName server1.wiredbrain.priv
          Invoke-command -ComputerName Server1 -ScriptBlock { restart-service -Name DNS -force}
          Resolve-DnsName -Name dc1.wiredbrain.priv -Server server1.wiredbrain.priv

      #conditional Forwarders
          
          help Add-DnsServerConditionalForwarderZone -Full
          help Add-DnsServerConditionalForwarderZone -Examples
          Get-DnsServerZone -ComputerName DC1 | where 'ZoneType' -eq 'forwarder'

          #Add non-AD integrated conditional forwarder
            Add-DnsServerConditionalForwarderZone `
            -Name "appdevwb1.priv"`
            -MasterServers 192.168.95.40 `
            -ComputerName DC1
          
          #Add AD integrated conditional forwarder
            Add-DnsServerConditionalForwarderZone `
            -Name "appdevwb2.priv" -ReplicationScope "Forest" `
            -MasterServers 192.168.95.40 `
            -ComputerName DC1

  #endregion Demo2:forwaders

  #region Demo3:DNS Zones

    #Query DNS Zones
        Get-DnsServerZone -ComputerName dc1
        
        Get-DnsServerZone `
            -Name wiredbrain.priv `
            -ComputerName DC1.wiredbrain.priv | fl

    #Create Reverse Lookup for 192.168.95.0
        Add-DnsServerPrimaryZone `
            -ComputerName DC1 `
            -NetworkID "192.168.95.0/24" `
            -ReplicationScope "Forest" -Verbose
    
    #Create File-Based Zone on Server1 for appdevwb.priv
        Add-DnsServerPrimaryZone `
            -ComputerName Server1.wiredbrain.priv `
            -ZoneName appdevwb.priv `
            -ZoneFile 'appdevwb.priv.dns' -Verbose

        get-childitem -Path \\server1\c$\windows\system32\dns #CheckPath to verify file
        
        Get-DnsServerZone -ComputerName server1
    #Create Secondary for appdevwb.priv on DC1
        Set-DnsServerPrimaryZone `
            -Name appdevwb.priv `
            -ComputerName Server1.wiredbrain.priv `
            -SecondaryServers 192.168.95.20 `
            -SecureSecondaries TransferToSecureServers
        
        Add-DnsServerSecondaryZone `
            -Name appdevwb.priv `
            -ComputerName DC1.wiredbrain.priv `
            -MasterServers 192.168.95.40 `
            -ZoneFile 'appdevwb.priv.dns'

        Start-DnsServerZoneTransfer `
            -ComputerName DC1.wiredbrain.priv `
            -ZoneName appdevwb.priv `
            -FullTransfer

		Get-DnsServerZone -Name appdevwb.priv -ComputerName DC1.wiredbrain.priv
 
    #Convert Zone to AD-Integrated
        Add-DnsServerPrimaryZone `
            -ComputerName DC1.wiredbrain.priv `
            -ZoneName moarcoffee.priv `
            -ZoneFile 'moarcoffee.priv.dns'

        ConvertTo-DnsServerPrimaryZone `
            -ComputerName DC1 `
            -Name moarcoffee.priv `
            -ReplicationScope Domain `
            -PassThru `
            -Verbose `
            -Force
    #Remove Moarcoffee.priv zone
        Remove-DnsServerZone `
            -Name 'moarcoffee.priv' `
            -ComputerName DC1 -Verbose

        Get-DnsServerZone -ComputerName DC1
  #endregion Demo3:DNS Zones
  
  #region Demo4:Records 

      #Viewing Records
        #All
        Get-DnsServerResourceRecord `
            -ZoneName wiredbrain.priv `
            -ComputerName DC1
        
        #By Type
        Get-DnsServerResourceRecord `
            -ZoneName wiredbrain.priv `
            -Name DC1 `
            -RRType A `
            -ComputerName DC1 | fl

      #Create Records
        #A
        Add-DnsServerResourceRecordA `
            -ZoneName wiredbrain.priv `
            -Name Server5 `
            -IPv4Address 192.168.95.60 `
            -CreatePtr `
            -ComputerName DC1 `
            -Verbose  
        #Cname
        Add-DnsServerResourceRecordCName `
            -ZoneName wiredbrain.priv `
            -HostNameAlias server5.wiredbrain.priv `
            -Name Mail `
            -ComputerName dc1 `
            -Verbose

        Resolve-DnsName -Name mail.wiredbrain.priv -Server DC1
        
        #MX
        Add-DnsServerResourceRecordMX `
            -Zonename wiredbrain.priv `
            -Name . `
            -MailExchange mail.wiredbrain.priv `
            -Preference 5 `
            -ComputerName DC1 `
            -Verbose

        Get-DnsServerResourceRecord -ZoneName wiredbrain.priv -ComputerName DC1

  #endregion Demo4:Records 

  
