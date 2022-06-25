#include "CProcess.h"
#include <stdexcept>
#include <string>
#include <iostream>

CProcess::CProcess(PROCESS_INFORMATION & processInformation, STARTUPINFOA & startupProcessInformation)
{
    this->processInformation = processInformation;
	this->startupProcessInformation = startupProcessInformation;
    this->isProcessSuspended = false;
}

CProcess::CProcess(const char* filePath, DWORD flags)
{
    this->processInformation = {0};
	this->startupProcessInformation = {0};

    if(!CreateProcessA(filePath, NULL, NULL, NULL, FALSE, flags, NULL, NULL, &this->startupProcessInformation, &this->processInformation)){
        throw std::runtime_error(std::string("Error creating new process. GetLastError=") + std::to_string(GetLastError()));
    }

    if(flags & CREATE_SUSPENDED){
        this->isProcessSuspended = true;
    }
}

CProcess::~CProcess()
{
}


void CProcess::replaceProcessImage(CPeImage& image){
    
}
