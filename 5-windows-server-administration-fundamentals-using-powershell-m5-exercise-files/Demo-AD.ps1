#Demos - Administering Active Directory

#region Demo - Installing Active Directory
    #Install AD
    Install-WindowsFeature -ComputerName Server1 -Name AD-Domain-Services
    Enter-PSSession -ComputerName Server1
    Get-Command -Module ADDSDeployment
    Install-ADDSDomainController `
        -Credential (Get-Credential) `
        -InstallDns:$True `
        -DomainName 'wiredbrain.priv' `
        -DatabasePath 'C:\Windows\NTDS' `
        -LogPath 'C:\Windows\NTDS' `
        -SysvolPath 'C:\Windows\SYSVOL' `
        -NoGlobalCatalog:$false `
        -SiteName 'Default-First-Site-Name' `
        -NoRebootOnCompletion:$False `
        -Force
    Exit-PSSession
    
    #Verify DCs in Domain
    Get-DnsServerResourceRecord -ComputerName Server1 -ZoneName wiredbrain.priv -RRType Ns
    Get-ADDomainController -Filter * -Server Server1 |
        ft Name,ComputerObjectDN,IsGlobalCatalog
#endregion Demo1

#region Demo2 - Gathering information in Active Directory
    #View AD Hieararchy
    get-adobject -Filter * |ft name,objectclass
    
    Get-ADObject -Filter {ObjectClass -eq "OrganizationalUnit"}
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}|
        FT Name,DistinguishedName -AutoSize
    
    #Find Objects
    get-adobject -Filter * | gm
    
    get-adobject -Filter * -Properties * | gm # -properties * brings extended Properties
    
    Get-ADObject -Filter {(name -like '*bender*') -and (ObjectClass -eq 'user')} -Properties *|
        ft Name,DistinguishedName
    
    #Finding specific user objects
    Get-ADObject `
        -Identity 'CN=Mike Bender-Admin,OU=Users,OU=Madison,OU=CompanyOU,DC=wiredbrain,DC=priv' `
        -Properties * | FL

    get-adobject -Filter {SamAccountName -eq 'mbadmin'} -Properties * | FL

    #Add OU for Users and Computer under Austin
    New-ADOrganizationalUnit `
        -Name Users `
        -Path 'OU=Austin,OU=CompanyOU,DC=WiredBrain,DC=Priv' `
        -Verbose
    
    New-ADOrganizationalUnit `
        -Name Computers `
        -Path 'OU=Austin,OU=CompanyOU,DC=WiredBrain,DC=Priv' `
        -Verbose
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}
#endregion Demo2

#region Demo3 - users

#Get User Information
get-aduser -Filter * -Properties *| gm

get-ADUser -Filter * -Properties *| fl Name,DistinguishedName,City

Get-ADUser -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv'|
     ft Name,DistinguishedName -AutoSize

Get-ADUser -Filter {Name -like '*bender*'}  -Properties * |
 ft Name,DistinguishedName -AutoSize

Get-aduser -Identity 'mbadmin' -Properties *

#Find all users in Madison and in IT department; Export to CSV file 

get-aduser -Filter {(City -eq 'Madison') -and (department -eq 'IT')} -Properties *|
    select-object Name,City,Enabled,EmailAddress|
    export-csv -Path C:\demos\Demo-M5\MadUsers.csv

notepad C:\demos\Demo-M5\MadUsers.csv

#Create a New user with PowerShell
    $SetPass = read-host -assecurestring
    New-ADUser `
        -Server DC1 `
        -Path 'OU=Users,OU=Madison,OU=CompanyOU,DC=WiredBrain,DC=Priv' `
        -department IT `
        -SamAccountName TimJ `
        -Name Timj `
        -Surname Jones `
        -GivenName Tim `
        -UserPrincipalName Timj@wiredbrain.priv `
        -City Madison `
        -AccountPassword $setpass `
        -ChangePasswordAtLogon $True `
        -Enabled $False -Verbose 
    
    Get-ADUser -Identity 'Timj'

#Modify single user object
Set-ADuser -Identity 'timJ' -Enabled $True -Description 'Tim is a demo User' -Title 'Demo User'
Get-ADUser -Identity 'Timj' -Properties *| FL Name,Description,Title,Enabled

#Modify Existing users without state of Wisconsin
Get-ADUser  `
    -filter { ( State -eq $null) } `
    -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv' -SearchScope Subtree|
    ft Name,SamAccountName,City

Get-ADUser  `
    -filter { -not( State -like '*') } `
    -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv' -SearchScope Subtree -Properties *|
    ft Name,SamAccountName,State

Get-ADUser  `
    -filter { -not( City -like '*') } `
    -SearchBase 'OU=CompanyOU,DC=WiredBrain,DC=Priv' -SearchScope Subtree|
    Set-ADUser -State 'WI' -Verbose

get-aduser -Filter {State -eq 'WI'} -Properties *|
        ft name,SamAccountName,State

#Find users that are disabled
    get-aduser -Filter {enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Madison,OU=CompanyOU,DC=WiredBrain,DC=Priv'|
        ft Name,SamAccountName,Enabled -AutoSize

    get-aduser -Filter {enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Madison,OU=CompanyOU,DC=WiredBrain,DC=Priv'|
        Set-ADUser -Enabled $true

    get-aduser -Filter * `
        -SearchBase 'OU=Users,OU=Madison,OU=CompanyOU,DC=WiredBrain,DC=Priv'|
        ft Name,SamAccountName,Enabled -AutoSize

#Determine status of LockedOut Account
    Search-ADAccount -LockedOut | select Name  
        
    Unlock-ADAccount -Identity 'mbtest'

#Reset Password
    $newPassword = (Read-Host -Prompt "Provide New Password" -AsSecureString)

    Set-ADAccountPassword -Identity mbtest -NewPassword $newPassword -Reset

    Set-ADuser -Identity mbtest -ChangePasswordAtLogon $True

#endregion Demo3

#region Demo4 - Computers

#Find all computers in domain
Get-ADComputer -Filter * -Properties * |ft Name,DNSHostName,OperatingSystem

Get-adcomputer -Filter {OperatingSystem -eq 'Windows 10 Enterprise Evaluation'} -Properties *|
    ft Name,DNSHostName,OperatingSystem

#View information for server1
Get-ADComputer -Identity 'Server1' -Properties *

#Modify Description on Computer 
Set-ADComputer -Identity 'Server1' -Description 'This is a Server for App/Dev Testing' -PassThru|
    Get-ADComputer -Properties * | ft Name,DNSHostName,Description

#Move computer to OU
Get-ADComputer -Identity Server1 |
    Move-ADObject -TargetPath 'OU=Computers,OU=Austin,OU=CompanyOU,DC=WiredBrain,DC=Priv'

Get-ADComputer -Identity Server1 -Properties * | FT Name,DistinguishedName
#endregion Demo4

#region Demo5 - Groups
#View all Groups
Get-ADGroup -Filter * -Properties *| FT Name,Description -AutoSize -Wrap

#View Specific Group
get-adgroup -Identity 'Domain Users' -Properties *

#create a new group for IT users
New-ADGroup `
    -Name 'IT Users' `
    -GroupCategory Security `
    -GroupScope Global

Set-ADGroup -Identity 'IT Users' -Description 'This is a group for IT Users'

get-adgroup -Identity 'IT Users' -Properties * | fl Name,Description

#View Group Membership of Group
Get-ADGroupMember -Identity 'Domain Users'|ft Name

#Add Users to Group for IT
Get-ADGroupMember -Identity 'IT Users'

Add-ADGroupMember `
    -Identity 'IT Users' `
    -Members (get-aduser -Filter {department -eq 'IT'})

Get-ADGroupMember -Identity 'IT Users'|ft Name

#Remove IT Users Group
Remove-ADGroup -Identity 'IT Users'

#endregion Demo5