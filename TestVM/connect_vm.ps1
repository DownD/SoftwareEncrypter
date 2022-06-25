# Connect to VM
vmconnect.exe localhost WINLABVM

# Start VM
Start-VM WINLABVM


# Execute on VM once to set it up
#$vmcreds = Get-Credential
#Invoke-command -VMName WINLABVM -Credential $vmcreds -FilePath Setup-VM-WINLABVM.ps1

# Get Ip Address of VM
#Get-NetIPAddress -AddressFamily Ipv4 | Select-Object InterfaceAlias, IPv4Addresstw