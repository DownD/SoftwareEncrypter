#pragma once
#include <windows.h>
#include "CPeImage.h"

class CProcess
{
    public:

        //Attaches to a process
        CProcess(PROCESS_INFORMATION & processInformation, STARTUPINFOA & startupProcessInformation);

        //Creates a new process in suspended state if the flags variable is not provided
        CProcess(const char* filePath, DWORD flags = CREATE_SUSPENDED);
        ~CProcess();

        //Preform the process hollowing technique
        void replaceProcessImage(CPeImage& image);

    private:
    	PROCESS_INFORMATION processInformation;
	    STARTUPINFOA startupProcessInformation;
        
        // This variable is not automatically synced with the process
        bool isProcessSuspended;
};

