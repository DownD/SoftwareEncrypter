<#
    (c) CodeMachine Inc. 2000-2021.  www.codemachine.com

    Run this script on the Host System to create a new Windows VM.
    Will create a new Internal Network virtual switch called LABNET.
    Will create a new Hyper-V VM with the name WINLABVM.
#>

### BEGIN CUSTOMIZE
# Modify $vmname, $switch, $vhdpath, $isopath as necessary
$vmname = "WINLABVM"
$switch = "LABNET"
$isopath = 'C:\Users\migue\source\repos\Crypter\TestVM\Windows.iso'
$vhdpath = (Get-VMHost).VirtualHardDiskPath + $vmname + ".vhdx"
$pipename = "\\.\pipe\" + $vmname
### END CUSTOMIZE

# Check if the path to the .ISO is valid
if ( (Test-Path $isopath -PathType Leaf) -ne $True ) {
    throw "Missing .ISO `"$isopath`""
}

# Enable Hyper-V Platform feature
if ( (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -ne "Enabled" ) {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
}

# Turned off Enhanced Session Mode in Hyper-V
if ( (Get-VMHost).EnableEnhancedSessionMode -eq $True ) {
    Set-VMHost -EnableEnhancedSessionMode $False
}

# Create a new Hyper-V Internal Network switch
if ( (Get-VMSwitch $switch) -eq $null ) {
    New-VMSwitch -SwitchName $switch -SwitchType Internal
}

# Create a new VHD (VHDX Format, 30GB Size, Dynamically Expanding)
if ( (Test-Path $vhdpath -PathType Leaf) -ne $True ) {
    New-VHD -Dynamic -SizeBytes 30GB -Path $vhdpath
}

# Create a new VM (GEN 2, 2GM RAM, NIC=LABNET, VHDX)
if ( (Get-VM -Name $vmname -ErrorAction SilentlyContinue ) -eq $null ) {
    New-VM -Name $vmname -MemoryStartupBytes 2GB -Generation 2 -SwitchName $switch -VHDPath $vhdpath

    # Add a Windows Bootable .ISO file as a DVD Drive to the VM
    $dvddrive = Get-VMDvDDrive -VMName $vmname
    if ( $dvddrive -eq $null ) {
        $dvddrive = Add-VMDvdDrive -VMName $vmname -Path $isopath 
    }

    # Turn off automatic checkpoints (Uncheck "use automatic checkpoints")
    # Set the checkpoint type to Standard (as opposed to production)
    # Set the VM to only use the memory allocated at startup (uncheck "Enable Dynamic Memory")
    # Configure the VM for multiple CPUs (Number of virtual processors: 2)
    Set-VM -VMName $vmname -AutomaticCheckpointsEnabled $False -CheckpointType Standard -StaticMemory -ProcessorCount 2

    # Turn off secure boot for kernel debugging (Uncheck "Enable Secure Boot")
    # Set the DVD drive as the preferred boot device
    Set-VMFirmware -VMName $vmname -EnableSecureBoot Off -BootOrder $dvddrive

    # Add Serial Port COM1 to the VM for Kernel Debugging
    Set-VMCOMPort -VMName $vmname -Number 1 -Path $pipename

    # Set the maximum resolution for the VM display to fit on a HD monitor
     Set-VMVideo -VMName $vmname -ResolutionType Maximum -HorizontalResolution 1280 -VerticalResolution 720
} else {
    throw "VM already exists: `"$vmname`""
}


