##Demo - IIS

#region Demo - Install Roles, Configure Management, Verify IIS
#Setup Windows 10 Client (Add Console and Scripts & Tools
appwiz.cpl

#Verify Commands are available from Web Administration PS module
get-command -Module WebAdministration

#Add IIS Tools
Start iexplore http://www.iis.net/downloads/microsoft/iis-manager #Save to c:\Demos 

#Install Web-Server role, ASP.Net role feature, and configure for Remote Management 
$ComputerName = 'Server1'
Invoke-command -ComputerName $ComputerName {
    install-WindowsFeature web-server,web-asp-net,Web-Mgmt-Service}

Invoke-Command -ComputerName $ComputerName {
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server `
    -Name EnableRemoteManagement -Value 1
    }

Invoke-Command -ComputerName $ComputerName {Set-Service wmsvc -StartupType Automatic}

Invoke-Command -ComputerName $ComputerName {restart-service wmsvc}

Start iexplore http://Server1

#Verify IIS Web sites
Enter-PSSession -ComputerName Server1
    Import-Module WebAdministration
    Get-website -name *
    Get-childitem -path IIS:\sites
    Exit-PSSession

#Connect to Server2 with IIS console
Start inetmgr

#endregion

#region Demo-Default Web Page

#Set Default Web Page for IIS to custom ASP.net test page

    #Copy file from share to c:\inetpub\wwroot
    Invoke-Command -ComputerName Server1 {
    
        Import-Module WebAdministration

        copy-Item `
            -Path \\dc1\Demos\Demo-IIS\TestPage.asp `
            -Destination \\Server1\c$\inetpub\wwwroot

        }
        notepad \\server1\c$\inetpub\wwwroot\testpage.asp

            
        Start iexplore http://Server1/testpage.asp

        #More information on IIS Server Variables
        start iexplore 'https://msdn.microsoft.com/en-us/library/ms524602(v=vs.90).aspx'    

    #View and edit Default Documents on Webserver
    Invoke-Command -ComputerName Server1 {
    
        Import-Module WebAdministration
        
        Get-WebConfiguration -filter system.webserver/defaultdocument/files/add `
            -PSPath iis:\ | ft value
        }

    Invoke-Command -ComputerName Server1 {
        Add-Webconfiguration -filter system.webserver/defaultdocument/files `
            -pspath iis:\ -value 'testpage.asp'
        
        }
    
    #verify default webpage has modified
    Start iexplore http://Server1
#endregion

#region - Demo New Web Page

    #configure internal DNS zone for moarcoffee.com
    Add-DnsServerPrimaryZone `
        -ComputerName Server1 `
        -Name moarcoffee.com `
        -ReplicationScope Domain

    Add-DnsServerResourceRecord `
        -ComputerName Server1 `
        -ZoneName moarcoffee.com `
        -A www `
        -IPv4Address 192.168.95.40

    Resolve-DnsName www.moarcoffee.com -Server Server1


    #Create new website and application pool
    Enter-PSSession -ComputerName Server1
        Import-Module WebAdministration
        
        $SitePath = 'c:\Websites\MoarCoffee'
        
        new-item -ItemType Directory -Path $SitePath
    
        copy-Item -Path \\dc1\Demos\Demo-IIS\TestPage.asp `
            -Destination  \\server1\c$\Websites\moarcoffee
        
        New-WebappPool -name MoarCoffeePool
    
        New-Website -name MoarCoffee `
            -HostHeader www.MoarCoffee.com `
            -physicalPath $SitePath `
            -ApplicationPool MoarCoffeePool
    
        get-childitem IIS:\AppPools
        
        Restart-WebAppPool -Name Moarcoffeepool

        Get-ChildItem IIS:\sites

    Exit-PSSession
    
    
    Start iexplore http://www.moarcoffee.com
#endregion

#region IP Address Binding
#Create virtual IP address on nic
    Invoke-Command -ComputerName Server1 {
        Get-NetAdapter | select InterfaceAlias 
    }
        Invoke-Command -ComputerName Server1 {
        Get-NetIPAddress `
            -InterfaceAlias Ethernet0|
                ft IPAddress,InterfaceAlias,InterfaceIndex -AutoSize
    }
    
    Invoke-command -ComputerName Server1 {
        New-NetIPAddress `
            -IPAddress 192.168.95.90 `
            -PrefixLength 24 `
            -InterfaceAlias EtherNet0
  
    }


#create new website with IP address binding
    Enter-PSSession -ComputerName Server1
        Import-Module WebAdministration
        
        New-Item -ItemType directory -Path c:\websites\wiredbrain
        
        copy-Item -Path \\dc1\Demos\Demo-IIS\TestPage.asp `
            -Destination  c:\Websites\WiredBrain
       
        New-WebAppPool -name WiredBrainSite
        
        New-Website -Name WiredBrain `
            -IPAddress '192.168.95.90' `
            -physicalpath 'c:\websites\wiredbrain\' `
            -ApplicationPool WiredBrainSite 
    
    Exit-PSSession
    Start iexplore http://192.168.95.90

    Add-DnsServerResourceRecord -ComputerName Server1 `
        -ZoneName wiredbrain.priv `
        -A www `
        -IPv4Address 192.168.95.90

    Resolve-DnsName www.wiredbrain.priv -Server Server1
    Start iexplore http://www.wiredbrain.priv

    #Decide to add HostHeader to wiredbrain website at a later time
    Enter-PSSession -ComputerName Server1
        Import-Module WebAdministration
        Get-WebBinding -Name wiredbrain|
        set-WebBinding -Name WiredBrain `
            -Value 'www.wiredbrain.priv' `
            -PropertyName HostHeader
    Exit-PSSession

    Start iexplore http://www.wiredbrain.priv
#endregion

#region HostnameBinding
#Create DNS Zone and Record for coffeebrain.club
    Add-DnsServerPrimaryZone -ComputerName Server1 `
        -Name coffeebrain.club `
        -ReplicationScope Domain

    Add-DnsServerResourceRecord -ComputerName Server1 `
        -ZoneName coffeebrain.club `
        -A www `
        -IPv4Address 192.168.95.40

#Create a new website using hostname binding
    Enter-PSSession -ComputerName Server1
        
        Import-Module WebAdministration
        
        New-Item -ItemType directory -Path c:\websites\coffeebrain
        
        copy-Item -Path \\dc1\Demos\Demo-IIS\TestPage.asp `
                -Destination  c:\Websites\coffeeBrain
        New-WebAppPool -name CoffeeBrainSite
        
        New-Website -Name coffeeBrain `
            -HostHeader www.coffeebrain.club `
            -physicalpath c:\websites\coffeebrain `
            -ApplicationPool CoffeeBrainSite
    
    Exit-PSSession 
    
    start iexplore http://www.coffeebrain.club
#endregion

#region - Certificates pt1
#Create CSR/Certificate Signing Request for coffeebrain.club
certreq -v -?
notepad \\dc1\demos\Demo-IIS\request.inf

Invoke-command -ComputerName Server1 {
    certreq -new \\dc1\demos\Demo-IIS\request.inf \\dc1\demos\Demo-IIS\request.req
    }

#More Information on certreq.exe on Technet
start iexplore 'https://technet.microsoft.com/en-us/library/dn296456(v=ws.11).aspx'

#Copy CSR Text
notepad \\dc1\demos\Demo-IIS\request.req

#Go To 3rd party certificate issuer to create certificate request

#Download certificate .zip file to network location

#Extract Certificate for use
expand-archive `
    -Path \\dc1\demos\Demo-IIS\www_coffeebrain_club.zip `
    -DestinationPath \\dc1\demos\Demo-IIS
get-childitem -Path \\dc1\demos\Demo-IIS

#Accept certificate Request
Invoke-command -ComputerName Server1 {
    certreq -accept -machine \\dc1\demos\Demo-IIS\www_coffeebrain_club.cer
    } 

#Bind Certificate to Coffeebrain.club website
Enter-PSSession -ComputerName Server1
    Import-Module WebAdministration
    
    get-childitem -path Cert:\LocalMachine\My
    
    #Place Thumbprint of certificate into a variable
    $cert=get-childitem -path Cert:\LocalMachine\My |
        where subject -Like *coffeebrain*|
            select -ExpandProperty Thumbprint
    
    New-WebBinding -Name CoffeeBrain `
        -Protocol HTTPS `
        -IPAddress 192.168.95.40 `
        -SslFlags 0
    
    Get-ChildItem -Path Cert:\LocalMachine\My\$Cert|
        new-item -path IIS:\SslBindings\192.168.95.40!443
    
    Get-childitem -path IIS:\SslBindings

Exit-PSSession

start iexplore https://www.coffeebrain.club
#endregion

#region - Certificates - Exporting and Importing
#Export PFX
Invoke-Command -ComputerName Server1 {
        $cert=get-childitem -path Cert:\LocalMachine\My |
            where subject -Like *coffeebrain*|
                select -ExpandProperty Thumbprint
        
        $pwd = (get-credential).Password

        Get-ChildItem -Path Cert:\LocalMachine\My\$Cert|                 
            Export-PfxCertificate `
                -Password $pwd `
                -FilePath C:\Websites\export.pfx
           }

$servers = 'Server1' # Specify all target nodes

Invoke-Command -ComputerName $servers {Get-ChildItem -Path c:\websites\}

#Import certificate
Invoke-Command -ComputerName $servers {
    Import-PfxCertificate `
        -FilePath C:\websites\export.pfx `
        -CertStoreLocation Cert:\LocalMachine\root `
        -Password (Get-Credential).Password}

#Remove all PFX files for security reasons
Invoke-Command -ComputerName $Servers {
    Remove-Item -Path C:\Websites\*.pfx -Force -Recurse}

#View Certificates installed
Invoke-Command -ComputerName $Servers {
    Get-ChildItem -Path Cert:\LocalMachine\ -Recurse|
        where subject -Like *coffeebrain*}

#Remove old certificate
Invoke-Command -ComputerName $servers {
    #Remove Old Cert
    Import-Module webadministration
    $cert = get-childitem -path Cert:\LocalMachine\My\ |
        where subject -Like *coffeebrain*|
            select -ExpandProperty Thumbprint 
    
    Remove-Item -path Cert:\LocalMachine\My\$cert
    
    Get-ChildItem -Path Cert:\LocalMachine\ -Recurse|
        where subject -Like *coffeebrain*
    
    Remove-item -path IIS:\SslBindings\192.168.95.40!443
    }

start iexplore https://www.coffeebrain.club

##Bind New Certificate
Invoke-Command -ComputerName $Servers {
    
    Import-Module WebAdministration
    
    $cert=get-childitem -path Cert:\LocalMachine\root |
        where subject -Like *coffeebrain*|
            select -ExpandProperty Thumbprint
   
    Get-ChildItem -Path Cert:\LocalMachine\root\$Cert|
        new-item -path IIS:\SslBindings\192.168.95.40!443
    
    Get-childitem -path IIS:\SslBindings
}

start iexplore https://www.coffeebrain.club
#endregion


