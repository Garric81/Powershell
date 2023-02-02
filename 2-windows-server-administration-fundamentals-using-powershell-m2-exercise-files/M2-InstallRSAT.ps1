###Module 2 Demo###

##Before We begin, we need the Remote Server Adminstration Tools
## Download from https://www.microsoft.com/en-us/download/details.aspx?id=45520

##Clip:Install RSAT


##View Installed cmdlets/functions
Get-command 
(Get-Command).Count
Get-command -Module DHCPServer

#Install RSAT Tools
C:\demos\WindowsTH-RSAT_TP5-x64.msu

##view Installed cmdlets/functions
Get-command -Module DHCPServer
(Get-Command).Count
Get-command -Module DHCPServer

#Update Help Files locally
Update-help -Force

Help Get-Service

