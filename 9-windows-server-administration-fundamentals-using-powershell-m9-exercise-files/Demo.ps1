#Demo - Hyper-v

#region Install and Prep



#Verify Requirements
Invoke-Command -ComputerName Server2 -ScriptBlock {systeminfo.exe}

#Install Hyper-v Role & PowerShell Module on Remote Server  
Install-WindowsFeature -Name Hyper-V,Hyper-v-PowerShell -ComputerName Server2  -Restart

#Install Hyper-v Module for Windows PowerShell on Windows 10 client via Programs and features

#Import Hyper-V v1 Module for managing 2012 R2 from Windows 10
Import-Module Hyper-V -RequiredVersion 1.1 

#Review Hyper-V cmdlets
Get-Command -Module Hyper-V -Verb get

#Verify Hyper-V installed
Get-VMHost -ComputerName Server2 | fl

Invoke-command -ComputerName Server2 {
    get-service -ComputerName server2.wiredbrain.priv -Name VMMS}

#endregion Demo1

#region Create VM

# Default VHD location: -C:\Users\Public\Documents\Hyper-V\­Virtual Hard Disks
# Default VM Configuration files location -C:\ProgramData\Microsoft\Windows\Hyper-V

#Create VM Folder
    Invoke-Command `
        -ComputerName Server2 `
        {new-Item -ItemType Directory -Path c:\ -name HyperV}

#Create Virtual Machine Switch and add Production network adapter
    Invoke-Command `
        -ComputerName Server2 `
        {Get-NetAdapter -CimSession (new-cimsession -ComputerName Server2)}   

    New-VMSwitch -Name WiredBrain_LAN `
        -NetAdapterName Production `
        -ComputerName Server2

    Get-VMSwitch -ComputerName Server2

#Create VHD for VM
    New-VHD `
        -ComputerName Server2 `
        -Path c:\Hyperv\VM1\VM1.vhdx `
        -Dynamic `
        -SizeBytes 40gb

# Create Virtual Machine
    New-VM -Name VM1 `
        -ComputerName Server2 `
        -VHDPath c:\Hyperv\VM1\VM1.vhdx `
        -MemoryStartupBytes 512MB `
        -BootDevice CD

#Add Network Adapter
    Get-VM -ComputerName Server2 -Name VM1|
        Get-VMNetworkAdapter

    Get-VM -ComputerName Server2 -Name VM1|
        Get-VMNetworkAdapter|
            Connect-VMNetworkAdapter -SwitchName 'WiredBrain_LAN'

    Get-VM -ComputerName Server2 -Name VM1|
        Get-VMNetworkAdapter

#Bulk Create VMs
    $X=5
    do {
        $vm = "VM-$x"
        $VHD = "c:\Hyperv\$vm\$vm.vhdx"
         New-VHD `
            -ComputerName Server2 `
            -Path $vhd `
            -Dynamic `
            -SizeBytes 40gb

         New-VM -Name VM-$x `
            -ComputerName Server2 `
            -VHDPath $vhd `
            -MemoryStartupBytes 512mb `
            -BootDevice CD 
         
         Get-VM -ComputerName Server2 -Name $vm|
            Get-VMNetworkAdapter|
                Connect-VMNetworkAdapter -SwitchName 'WiredBrain_LAN'
         $x++  
       }
    until ($x -gt 10)

    Get-VM -ComputerName Server2

#Viewing VM Files
    Enter-PSSession -ComputerName Server2
    Set-Location -Path c:\ProgramData\Microsoft\Windows\Hyper-V

#endregion Demo2

#region Managing VMs and Virtual Hardware

#Start-VM
    get-vm -ComputerName Server2|ft
    
    Start-VM -Name VM1,VM-10 -ComputerName Server2
    
    get-vm -ComputerName Server2|ft

#Start all VMs on a Server
    Get-VM -ComputerName server2 | start-vm -WhatIf

#Stop VM
    stop-VM -ComputerName Server2 -Name VM1,vm-10 -TurnOff

#Place all VMs on a Server in saved state for maintenance
    Get-VM -ComputerName server2 |Stop-VM -Save -WhatIf
    
    Start-VM -Name VM1,VM-10 -ComputerName Server2

#Remove VM
    Remove-vm -ComputerName Server2 -Name VM-10 -Force

#Modify VM Stop Action
    Set-VM -Name vm1 `
        -ComputerName Server2 `
        -AutomaticStopAction Save

    Get-VM -ComputerName server2|
        Set-VM -AutomaticStopAction Save -WhatIf

#Working with Disks
    #Use Enter-PSSession to run commands on remote system via console
        Enter-PSSession -ComputerName Server2

    #view VHD on Server
        Get-VHD -ComputerName server2 -Path c:\Hyperv\VM1\VM1.vhdx
        
    #Resize VHD
        help Resize-VHD
        Resize-VHD `
            -ComputerName Server2 `
            -Path c:\Hyperv\VM-9\VM-9.vhdx `
            -SizeBytes 60gb
        
        get-vhd -Path C:\HyperV\vm-9\VM-9.vhdx
    
    #Optimize VHD
        help Optimize-VHD 
        Optimize-VHD `
            -ComputerName Server2 `
            -Path c:\Hyperv\VM1\VM1.vhdx `
            -WhatIf

    #Convert VHD to VHDX
    New-VHD `
        -ComputerName Server2 `
        -Path c:\Hyperv\VM2\VM2.vhd `
        -Dynamic `
        -SizeBytes 40gb

    Convert-VHD `
        -Path c:\Hyperv\VM2\VM2.vhd `
        -ComputerName Server2 `
        -DestinationPath c:\HyperV\VM2\VM2v2.vhdx `
        -VHDType Dynamic

    get-vhd -Path c:\HyperV\VM2\VM2v2.vhdx



#endregion 

#region Managment Tasks


#Checkpoint
    Checkpoint-vm -ComputerName Server2 -SnapshotName 'Demo Snapshot' -Name VM1
    Get-VMSnapshot -ComputerName Server2 -VMName VM1

    Checkpoint-vm -ComputerName Server2 -SnapshotName 'Demo Snapshot2' -Name VM1
    Get-VMSnapshot -ComputerName Server2 -VMName VM1

    Checkpoint-vm -ComputerName Server2 -SnapshotName 'Demo Snapshot3' -Name VM1
    Get-VMSnapshot -ComputerName Server2 -VMName VM1

    Remove-VMSnapshot -ComputerName Server2 -VMName VM1 -Name 'Demo Snapshot2'
    Remove-VMSnapshot -ComputerName Server2 -VMName VM1 -Name 'Demo Snapshot' -IncludeAllChildSnapshots

#Export a Virtual Machine
    Export-VM -Name 'VM1' -Path c:\ExportVM
    dir c:\exportVM -Recurse 

#View VMs in Hyper-V Manager

#endregion 