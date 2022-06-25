#pragma warning (disable : 4100)

#include <ntifs.h>
#include "message.h"


//Unload driver
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject){
    DebugMessage("Driver Unloaded");
    return STATUS_SUCCESS;
}

//Entry point of the driver
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING registryPath){
    pDriverObject->DriverUnload = DriverUnload;
    DebugMessage("Driver Loaded");
    return STATUS_SUCCESS;
}