#Demo - Group Policy

#region Demo1
#Review Group Policy in Editor

#View all GPOs in Domain

get-gpo -all -Domain wiredbrain.priv | ft DisplayName,GPOStatus,Description -AutoSize

#Review a Specific GPO
Get-GPO -Name 'Demo GPO'

Get-GPOReport -Name 'Demo GPO' -ReportType Xml -Path C:\demos\Demo-M6\gpreport.xml
Notepad C:\demos\Demo-M6\gpreport.xml

Get-GPOReport -Name 'Demo GPO' -ReportType Html -Path C:\demos\Demo-M6\gpreport.html
C:\demos\Demo-M6\gpreport.html

#Review Group Policy Settings Reference for Windows and Windows Server webpage
#https://www.microsoft.com/en-us/download/details.aspx?id=25250

#Review spreadsheet for Windows10

#Review ADMX Files and view ControlPanel.admx for setting no control panel
C:\Windows\PolicyDefinitions\desktop.admx

#Example
Set-GPRegistryValue `
    -Name 'Demo GPO' `
    -key HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System `
    -ValueName Wallpaper `
    -Type String `
    -value \\DC1\demos\demogp\Theme1\img4.jpg -Verbose

#endregion Demo1

#region Demo2

#create a GPO
New-gpo 'No Control Panel' `
    -Comment 'This setting is designed to prevents users from accessing CP.' 

get-gpo -Name 'No Control Panel'

Set-GPRegistryValue `
    -Name 'No Control Panel' `
    -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -ValueName 'NoControlPanel' `
    -Value 1 `
    -Type DWord

Get-GPOReport -Name 'No Control Panel' -ReportType Html -Path C:\demos\Demo-M6\NoControlPanel.html

C:\demos\Demo-M6\NoControlPanel.html

#endregion

#region
#Link GPO to Users OU under Austin OU
New-GPLink `
    -Name 'No Control Panel' `
    -Target 'OU=Users,OU=Austin,OU=CompanyOU,DC=wiredbrain,DC=priv' `
    -LinkEnabled No

Get-GPOReport -Name 'No Control Panel' -ReportType Html -Path C:\demos\Demo-M6\NoControlPanel.html

C:\demos\Demo-M6\NoControlPanel.html

#Enable/Disable GPO

Set-GPLink `
    -Name 'No Control Panel' `
    -LinkEnabled Yes `
    -Enforced No `
    -target 'OU=Users,OU=Austin,OU=CompanyOU,DC=wiredbrain,DC=priv'

#Enforce GPO
Set-GPLink `
    -Name 'No Control Panel' `
    -LinkEnabled Yes `
    -Enforced yes `
        -target 'OU=Users,OU=Austin,OU=CompanyOU,DC=wiredbrain,DC=priv'

#Block GPO
Set-GPInheritance `
    -Target 'OU=Computers,OU=Austin,OU=CompanyOU,DC=Wiredbrain,dc=Priv' `
    -IsBlocked Yes `
    -Domain Wiredbrain.priv `
    -Server DC1

#View GPOInheritance
Get-GPInheritance `
    -Target 'OU=Computers,OU=Austin,OU=CompanyOU,DC=Wiredbrain,dc=Priv' -Domain wiredbrain.priv

#endregion Demo2

#region Demo - GP In Action
    #Change Desktop Backgrounds to see how processing works
    #Domain Level Policy: img1.jpg (Beach)
    #CompanyOU level Policy: img3.jpg (Rock)
    #Users OU in Madison Level Policy: img2.jpg (Sea)

    #Enable Remote Scheduled Tasks Management firewall rules
    Invoke-Command `
     -ComputerName Client2 `
     -ScriptBlock {Get-NetFirewallRule -Name *RemoteTask*|Set-NetFirewallRule -Enabled True}
    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0

    #Login without policies applied

    #Enable Demo GPO-Beach at Domain Level
    set-gplink -Name 'Demo GPO-Beach' `
        -LinkEnabled Yes `
        -Target 'DC=Wiredbrain,dc=Priv'
    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0
    
    #Enable Demo GPO-ROCK at CompanyOU level
    set-gplink -Name 'Demo GPO-rock' `
        -LinkEnabled Yes `
        -Target 'OU=CompanyOU,DC=Wiredbrain,dc=Priv'
    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0

   #Set Blocking of OUs at Users level and Enable Demo GPO-sea at Users level
    Set-GPInheritance `
        -Target 'OU=Users,OU=Madison,OU=CompanyOU,DC=Wiredbrain,dc=Priv' `
        -IsBlocked Yes `
        -Domain Wiredbrain.priv `
        -Server DC1
    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0

    Set-GPLink -Name 'Demo GPO-Sea' `
        -LinkEnabled Yes `
        -Target 'OU=Users,OU=Madison,OU=CompanyOU,DC=Wiredbrain,dc=Priv'
    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0

    #Set Enforcement
    Set-GPLink -Name 'Demo GPO-rock' `
        -LinkEnabled Yes `
        -Enforced yes `
        -Target 'OU=CompanyOU,DC=Wiredbrain,dc=Priv' 

    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0
 
    #Change Permissions
    New-ADGroup `
    -Name 'Group Policy Users' `
    -GroupCategory Security `
    -GroupScope Global

    Add-ADGroupMember -Identity 'Group Policy Users' `
        -Members 'bobj'

    Get-GPPermission -Name 'Demo GPO-Rock' -All 
    
    Set-GPPermission -Name 'Demo GPO-rock' `
        -PermissionLevel GpoRead `
        -TargetName 'Authenticated Users' `
        -TargetType Group `
        -Replace
    
    Set-GPPermission -Name 'Demo GPO-rock' `
        -PermissionLevel GpoApply `
        -TargetName 'Group Policy Users' `
        -TargetType Group
    
    Get-GPPermission -Name 'Demo GPO-Rock' -All 
    
    Set-GPLink -Name 'Demo GPO-Sea' `
        -LinkEnabled No `
        -Target 'OU=Users,OU=Madison,OU=CompanyOU,DC=Wiredbrain,dc=Priv'
    
    Set-GPLink -Name 'Demo GPO-Sea' `
        -LinkEnabled Yes `
        -Target 'OU=Users,OU=Madison,OU=CompanyOU,DC=Wiredbrain,dc=Priv'

    Invoke-GPUpdate -Computer client2 -Force -RandomDelayInMinutes 0

    #Running Resultant Set of Policies report on user logging on client2
    Get-GPResultantSetOfPolicy `
    -User wiredbrain\bobj `
    -Computer client2.wiredbrain.priv `
    -ReportType Html `
    -Path C:\demos\Demo-M6\GPResult-bobj.html
    C:\demos\Demo-M6\GPResult-bobj.html

    #endregion Demo4D 