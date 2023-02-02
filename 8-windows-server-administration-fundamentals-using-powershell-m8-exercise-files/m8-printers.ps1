#Demos-Printers

#region - Gathering Information
#View Roles and Features
Get-WindowsFeature -ComputerName Server1 -Name *print*
Install-WindowsFeature -ComputerName Server1 -Name Print-Server

#View Print cmdlets
gcm -Name get-*print*

#Gathering Printer Information
get-printer -ComputerName DC1 | ft -AutoSize
get-printer -ComputerName DC1 -Name 'WB-Demo-1' -Full|fl

get-printer -ComputerName DC1 -Name 'WB-Demo-1' -Full|
     Get-PrintConfiguration |fl

Get-PrinterDriver -ComputerName DC1
Get-PrinterPort -ComputerName DC1

#endregion

#region - Adding Printers

#Adding a Printer to Server 
   #View drivers in Driver store
    Invoke-command -ComputerName Server1 {
         Get-windowsdriver -online -all |
             where {($_.classname -like “*print*”) -and ($_.ProviderName -like "*Lexmark*")}|
                fl Driver,Provider,OriginalFilename
        }

    notepad '\\server1\c$\windows\system32\driverstore\FileRepository\prnlxclv.inf_amd64_c29830f978cd4b85\prnlxclv.inf'
    
    Add-PrinterDriver -Name "Lexmark C734 Class Driver" -ComputerName Server1
    
    get-printerdriver -ComputerName Server1
    
    #Download Printer Files from Provider
    
    #Depending on type of file, may have to run installer/self-extractor
    
    #Self Extract Dell 1320c drivers to share
    \\dc1\Demos\Demo-Printer\1320c_DRV_ENG_01-01-06-00_01-01-06-00.exe
    
    #find x64 INF files
    $driver = (Get-ChildItem \\dc1\demos\Demo-Printer\*.inf -Recurse|
                    where directory -like *64*).FullName

    Get-ChildItem $driver

    invoke-command -ComputerName Server1 {
            $driver = (Get-ChildItem \\dc1\demos\Demo-Printer\*.inf -Recurse|
                            where directory -like *64*).FullName
            pnputil -i -a $driver
        }
    invoke-command -ComputerName Server1 {pnputil -e}
    
    #View INF file for name of driver
    notepad '\\server1\C$\windows\inf\oem1.inf'

    #Add Printer Components
    add-printerdriver `
       -Name 'Dell Color Laser 1320c' `
       -ComputerName Server1

    add-printerport `
        -Name '192.168.95.201' `
        -PrinterHostAddress '192.168.95.201' `
        -ComputerName Server1

    Add-Printer `
        -ComputerName Server1 `
        -DriverName 'Dell Color Laser 1320c' `
        -PortName '192.168.95.201' `
        -Comment 'Use this printer for default printer permissions' `
        -Shared -ShareName 'Dell1320c-1' `
        -Name 'Dell1320c-1' `
        -Published
   
   Get-Printer -ComputerName Server1

#endregion

#region - Setting Printer Permissions
#Setting Printer Permissions
    #Create Domain Local printer groups
    New-ADGroup `
        -Name 'Company-Manage-Printers' `
        -GroupCategory Security `
        -GroupScope DomainLocal

    New-ADGroup `
        -Name 'Company-Manage-Documents' `
        -GroupCategory Security `
        -GroupScope DomainLocal

    New-ADGroup `
        -Name 'Company-Users-Print' `
        -GroupCategory Security `
        -GroupScope DomainLocal
    
    #Modify 'Dell1320c-1' through print console with Permissions

    #Create 2nd Printer
    add-printerport `
        -Name '192.168.95.202' `
        -PrinterHostAddress '192.168.95.202' `
        -ComputerName Server1

    Add-Printer `
        -ComputerName Server1 `
        -DriverName 'Dell Color Laser 1320c' `
        -PortName '192.168.95.202' `
        -Comment 'This is a demo Printer' `
        -Shared -ShareName 'Dell1320c-2' `
        -Name 'Dell1320c-2' `
        -Published
    
    #Get Permission SDDL
    get-printer -ComputerName server1 -Full|fl name,PermissionSDDL

    $SDDL = Get-Printer –full –Name 'Dell1320c-1' -ComputerName Server1  |
     select PermissionSDDL -ExpandProperty PermissionSDDL

    #Add SDDL to existing printer
    set-printer `
        -ComputerName Server1 `
        -name 'Dell1320c-2' `
        -PermissionSDDL $SDDL `
        -Verbose
     
    get-printer -ComputerName server1 -Full |
        ft name,PermissionSDDL -AutoSize -Wrap
#endregion

#region - Managing Printer Settings
#Managing Printer Settings
 
    #Change Printer Configuration
    get-printer -ComputerName Server1 -Name 'Dell1320c-1'|
        Get-PrintConfiguration

    get-printer -ComputerName Server1 -Name 'Dell1320c-1'|
        Set-PrintConfiguration -DuplexingMode TwoSidedLongEdge
    
    #Change Comment
    Set-Printer -Name 'Dell1320c-2' `
        -ComputerName Server1 `
        -Comment 'Dell Color Laser 1320c - for use by all users.'

    get-printer -ComputerName Server1 -Name 'Dell1320c-2' -Full | fl
   
   #Change Printer Port to '192.168.95.205'
    add-printerport `
        -Name '192.168.95.205' `
        -PrinterHostAddress '192.168.95.205' `
        -ComputerName Server1
    
    Set-Printer -ComputerName Server1 -PortName '192.168.95.205' -Name 'Dell1320c-1'
    
    get-printer -ComputerName Server1 -Name 'Dell1320c-1'|fl


#Managing Print jobs
    get-command -Name *PrintJob*
    
    Get-PrintJob -ComputerName Server1 -PrinterName 'Dell1320c-2'|fl
    
    Remove-PrintJob -ComputerName Server1 -ID 2 -PrinterName 'Dell1320c-2'
    
    Suspend-PrintJob -ComputerName Server1 -ID 4 -PrinterName 'Dell1320c-2'

#Restart Printer Spooler
    Invoke-command -ComputerName Server1  {
        restart-service -Name Spooler
        }
#endregion

