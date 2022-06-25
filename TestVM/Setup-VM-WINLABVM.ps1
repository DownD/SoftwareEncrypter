<#
    (c) CodeMachine Inc. 2000-2021.  www.codemachine.com

    ***This script must be run in the Guest VM***.
    It configures the Guest VM for kernel debugging and
    memory dump generation. The Guest system SMB name will be 
    changed to WINLABVM.

    If are using Hyper-V, you can run this script *in the Guest VM*
    from the host using the PowerShell Direct service. To do so,
    start an administrative PowerShell window on the host and
    type in the lines below. When prompted enter the account name and
    password which you used while installing Windows in the Guest VM
    $vmcreds = Get-Credential
    Invoke-command -VMName WINLABVM -Credential $vmcreds -FilePath Setup-VM-WINLABVM.ps1

    If you are using VMWare or Virtual Box, you must
    copy this script to the Guest VM, 
    start an administrative PowerShell window on the Guest VM, 
    change to the directory containing the script, 
    and run the following commands.
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
    .\Setup-VM-WINLABVM.ps1
#>

### BEGIN CUSTOMIZE
# Modify $guestname  as necessary
$guestname = "WINLABVM"
# Modify $pubdir  as necessary
$pubdir = "c:\pub"
### END CUSTOMIZE

# Enable PowerShell script execution
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

# Enable File and Printer Sharing for the public network profile 
# The public network profile is assigned by default to interfaces with APIPA addresses
Set-NetFirewallRule -Group "@FirewallAPI.dll,-28502" -Profile Public -Enabled true

# Shared folder setup
New-Item -ItemType "directory" -Path $pubdir
New-SmbShare -Name "pub" -Path $pubdir -FullAccess "Everyone"

# Local symbol cache, since this VM will not be connected to the Internet, 
# the symbols will have to be manually copied from the host 
# Configure _NT_SYMBOL_PATH to point to c:\pub\sym
[System.Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', "SRV*$pubdir\sym", 'Machine')

# Add the path c:\pub to the Windows Defender list of excluded paths
Add-MpPreference -ExclusionPath $pubdir

# Backup the current boot manager profile in [original]
# Create two new boot manager profiles [testsign] and [debugger]
# Disable Automatic Repair when the system bugchecks
# Ignore errors if there is a failed boot, failed shutdown, or failed checkpoint.
bcdedit.exe --% /copy {current} /d "Windows 10 [original]"
bcdedit.exe --% /set {current} testsigning  ON
bcdedit.exe --% /copy {current} /d "Windows 10 [testsign]"
bcdedit.exe --% /debug {current} ON
bcdedit.exe --% /set {current} description "Windows 10 [debugger]"
bcdedit.exe --% /dbgsettings serial debugport:1 baudrate:115200
bcdedit.exe --% /set {current} recoveryenabled No
bcdedit.exe --% /set {current} bootstatuspolicy IgnoreAllFailures

# Create the "Debug Print Filter" key and value for DbgPrint()
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'  -Name 'Debug Print Filter'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter' -Name 'DEFAULT' -Type DWORD -Value 0xffffffff 

# System memory dump settings
# Configure the guest system to bug-check on receiving an NMI from the host.
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'NMICrashDump' -Type DWORD -Value 1

# Always retain system memory dump
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AlwaysKeepMemoryDump' -Type DWORD -Value 1

# Turn off Auto-reboot during bug-check
Get-WmiObject Win32_OSRecoveryConfiguration  | Set-WmiInstance -Arguments @{ AutoReboot=$False }

# Set DumpType to complete memory dump
Get-WmiObject Win32_OSRecoveryConfiguration  | Set-WmiInstance -Arguments @{ DebugInfoType=1 }

# Allow Memory dumps to be overwritten
Get-WmiObject Win32_OSRecoveryConfiguration  | Set-WmiInstance -Arguments @{ OverwriteExistingDebugFile=$True }

# Increase size of the paging file to accommodate a complete system memory dump
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile=$false}
Get-CimInstance Win32_PageFileSetting | Set-CimInstance -Property @{InitialSize=2064;MaximumSize=2064}

# Change the SMB name of the system
Rename-Computer -NewName $guestname