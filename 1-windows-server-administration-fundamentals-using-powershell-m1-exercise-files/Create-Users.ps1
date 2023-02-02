#UserSetup
$SetPass = read-host -assecurestring
$Users =Import-CSV "C:\shares\demos\setup\DemoUsers.csv" 
$cred = Get-Credential
#get-aduser -Filter * -Properties *| gm
ForEach ($user in $users){ 
    
    New-ADUser `
        -Credential $cred `
        -Path $user.DistinguishedName `
        -department $user.Department `
        -SamAccountName $user.SamAccountName `
        -Name $user.Name `
        -Surname $user.Surname `
        -GivenName $user.GivenName `
        -UserPrincipalName $user.UserPrincipalName `
        -City $user.city `
        -ChangePasswordAtLogon $False `
        -AccountPassword $SetPass `
        -Enabled $False -Verbose
        }
#Set accounts as enabled
    Set-ADUser -Identity 'mbtest' -Enabled $True
    set-aduser -Identity 'mbadmin' -enable $true

#Add mbadmin account to Admin Groups
Add-ADGroupMember -Identity 'Domain Admins' -Members 'mbadmin'
Add-ADGroupMember -Identity 'Enterprise Admins' -Members 'mbadmin'
Add-ADGroupMember -Identity 'Schema Admins' -Members 'mbadmin'