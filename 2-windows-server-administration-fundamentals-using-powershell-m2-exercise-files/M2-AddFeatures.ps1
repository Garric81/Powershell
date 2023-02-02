#Review Installed Roles and Features
Get-WindowsFeature -ComputerName Server1.wiredbrain.priv

Get-WindowsFeature -ComputerName Server1.wiredbrain.priv |
     where 'Installed' -eq $true

#Add Roles
Add-WindowsFeature -Name DNS -IncludeManagementTools

Add-WindowsFeature -name Web-Server -IncludeSubFeatures

