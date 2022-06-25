# Script that takes the build type as the first argument, copies the driver into the VM WINLABVM, and runs the driver.
# The script creates attempts to stop and delete a driver with the same name before running the driver.


# If the first argument was not specified then add a default value of "Release"
if ($args.count -eq 0){
    $buildType="Release"
}else{
    $buildType=$args[1]
}

# Credentials
$passwd = convertto-securestring -AsPlainText -Force -String "D0wnl0ad1"
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "dev",$passwd

Write-Output "Deploying driver for build type: $buildType"
Invoke-Command -VMName "WINLABVM" -credential $cred -ScriptBlock {

    sc.exe stop ProtectionKDriver
    sc.exe delete ProtectionKDriver
}
cls
Write-Output "Older driver Unloaded"

copy .\x64\$buildType\ProtectionKDriver.sys \\169.254.41.38\pub\ProtectionKDriver.sys

Invoke-Command -VMName "WINLABVM" -credential $cred -ScriptBlock {
    sc.exe create ProtectionKDriver type= kernel binpath= c:\pub\ProtectionKDriver.sys
    sc.exe start ProtectionKDriver
}

Write-Output "Deployment of driver for $buildType build completed"