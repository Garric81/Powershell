#Demos - File Services and Storage

#region - Add virtual disks and verify
    #Add Disks in VMware Workstation

    #Verify Disks added to Server1
    $cim = New-CimSession -ComputerName server1
    get-Disk -CimSession $cim
#endregion

#region - Disk Partitions and Volumes
    $cim = New-CimSession -ComputerName Server1
    #View Disk Information
    Get-Disk -CimSession  $cim
    
    Get-Disk -CimSession  $cim | fl
    
    get-Disk -CimSession $cim -Number 0 | fl
    
    Get-PhysicalDisk -CimSession $cim

    Get-PhysicalDisk -CimSession $cim -FriendlyName PhysicalDisk0 | fl
    
    #View Partitions 
    Get-partition -CimSession $cim

    #View Volumes
    Get-Volume -CimSession  $cim
    Get-Volume -CimSession  $cim -DriveLetter C | fl

    #Prepare Disks - Initialize RAW Disks
    Get-Disk -CimSession $cim |ft Number,Size,PartitionStyle -AutoSize
    
    Get-Disk -CimSession $cim |
        Where PartitionStyle -EQ 'RAW'|
            Initialize-Disk
    
    Get-Disk -CimSession $cim |ft Number,Size,PartitionStyle -AutoSize
    
    #Create Basic Volume -  Use *-partition for Basic Disk Partition/Volumes
    new-partition -CimSession $cim -DiskNumber 1 -Size 40GB
    
    Set-Partition -CimSession $cim `
        -PartitionNumber 2 `
        -NewDriveLetter E `
        -DiskNumber 1 

    Get-partition -CimSession $cim

    Format-Volume -DriveLetter E -FileSystem ReFS -CimSession $cim

    get-volume -CimSession $cim

#endregion

#region - Mirrored Volume
    #Run Diskpart.exe on console of Server1
    #Diskpart
        #diskpart>List volume
        #diskpart>List disk
        #diskpart>Select disk=1
        #diskpart>Convert dynamic
        #diskpart>Select disk=2
        #diskpart>Convert dynamic
        #diskpart>Select volume E
        #diskpart>Add disk=2
        #diskpart>List volume
        #diskpart>Exit

#endregion

#region - Storage Spaces
    #Reset Server1 Drives with DiskPart
   
    #Identitfy the physical disks available for pooling
    $cim = New-CimSession -ComputerName Server1
    Get-PhysicalDisk -CimSession $cim -CanPool $true
    
    #Create a Storage Pool
    $subID = (Get-StorageSubSystem -CimSession $cim -FriendlyName "*Space*").uniqueID
    $SPDisks = Get-PhysicalDisk -CanPool $true -CimSession $cim
    New-StoragePool -FriendlyName "StoragePool-1" `
        -CimSession $cim `
        -StorageSubSystemUniqueId $subID  `
        -PhysicalDisks $SPDisks
    
    Get-StoragePool -FriendlyName 'StoragePool-1' -CimSession $cim |fl
    
    #Create a Virtual Disk
    New-VirtualDisk -FriendlyName 'VirtualDisk-1' `
        -CimSession $cim `
        -StoragePoolFriendlyName 'StoragePool-1' `
        -Size 1TB `
        -ProvisioningType Thin `
        -ResiliencySettingName Mirror #Options include Simple, Mirror, Parity
    
    get-disk -CimSession $cim

    #Initialize the Virtual Disk
    Get-VirtualDisk -CimSession $cim -FriendlyName 'VirtualDisk-1' |
        Get-disk -CimSession $cim |
            Initialize-Disk
    #Create the Partition on the Virtual Disk
    New-Partition `
        -CIMSESSION $CIM `
        -DiskNumber 3 `
        -UseMaximumSize `
        -AssignDriveLetter

    #Format the Volume
    Format-Volume -DriveLetter E `
        -CimSession $CIM `
        -FileSystem ReFS `
        -NewFileSystemLabel "DataStore-1"

    Get-Volume -CimSession $cim
#endregion

#region - Shares
    #Folder Share Groups
    New-ADGroup -Name 'Folder-Share-Read' `
        -GroupScope DomainLocal `
        -GroupCategory Security
    
    New-ADGroup -name 'Folder-Share-Change' `
        -GroupScope DomainLocal `
        -GroupCategory Security
    
    #View Shares on Server
    $cimsession =New-CimSession -ComputerName DC1
    
    get-smbshare -CimSession $cimsession

    get-smbshare -CimSession $cimsession -Name Demos | fl

    Get-SmbShareAccess -CimSession $cimsession -Name Demos | fl

    new-item -ItemType Directory -Path \\dc1\demos\Demo-FileServices

    New-SmbShare -Name SharedFolder `
    -CimSession $cimsession `
    -Path c:\shares\demos\Demo-FileServices `
    -Description 'This is a shared directory for users.' `
    -FullAccess 'builtin\administrators' `
    -ChangeAccess 'wiredbrain\Folder-Share-Change' `
    -ReadAccess 'wiredbrain\Folder-Share-Read' `
    -FolderEnumerationMode AccessBased

    get-smbshare -CimSession $cimsession -Name SharedFolder | Get-SmbShareAccess

    New-SmbMapping -LocalPath x: -RemotePath \\dc1\SharedFolder

#endregion

#region - 
    #working with Permissions using icacls
    
    icacls /?
    #a sequence of simple rights:
    #            N - no access
    #            F - full access
    #            M - modify access
    #            RX - read and execute access
    #            R - read-only access
    #            W - write-only access
    #            D - delete access
    
    Enter-PSSession -ComputerName DC1

        icacls \\dc1\demos\Demo-FileServices\
      
        icacls \\dc1\demos\Demo-FileServices /grant mbtest:F
    
        icacls \\dc1\demos\Demo-FileServices /grant Folder-Share-Change:M

        icacls \\dc1\demos\Demo-FileServices /grant Folder-Share-Read:RX

        icacls \\dc1\demos\Demo-FileServices
    
    #Copying File Permissions File Permissions
    get-acl \\dc1\demos\Demo-FileServices | fl
    
    New-Item -ItemType directory -Name Demo-FileServices2 -Path \\dc1\demos
    
    (get-acl -Path \\dc1\demos\Demo-FileServices\).Access|
        ft AccessControlType,Identityreference

    (get-acl -Path \\dc1\demos\Demo-FileServices2\).Access|
        ft AccessControlType,Identityreference
     
     $ACL = get-acl -Path \\dc1\demos\Demo-FileServices\
     Set-Acl -Path \\dc1\demos\Demo-FileServices2\ -AclObject $ACL
     
     
    (get-acl -Path \\dc1\demos\Demo-FileServices\).Access|
        ft AccessControlType,Identityreference

    (get-acl -Path \\dc1\demos\Demo-FileServices2\).Access|
        ft AccessControlType,Identityreference 
#endregion

#region
#endregion

#region
#endregion
