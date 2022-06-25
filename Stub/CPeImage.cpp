#include "CPeImage.h"
#include <stdexcept>

CPeImage::CPeImage()
{
    this->imageWasParsed = false;
    this->imageSize = 0;
}

CPeImage::~CPeImage()
{
}

IMAGE_DOS_HEADER* CPeImage::getDOSHeader()
{
    if(!imageWasParsed)
        throw std::runtime_error("Image was not parsed yet");

    return this->dosHeader;
}

void CPeImage::parseBaseImage(void* imageBaseAddr, int size)
{
    this->imageBaseAddr = imageBaseAddr;
    this->dosHeader = (IMAGE_DOS_HEADER*)imageBaseAddr;
    this->imageSize = size;
    
    //Check for PE magic number
    if (this->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Image doesn't have the PE format IMAGE_DOS_SIGNATURE does not match");
    }
    parseImage();
    this->imageWasParsed = true;
}


CPeImage32::CPeImage32() : CPeImage()
{
}

CPeImage32::~CPeImage32()
{
}


void CPeImage32::parseImage()
{
    this->ntHeaders = this->dosHeader->e_lfanew + (IMAGE_NT_HEADERS32*)this->imageBaseAddr; 
    if (this->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Image doesn't have the PE format IMAGE_NT_SIGNATURE does not match");
    
    //Check for 32 bit architecture
    if (this->ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        throw std::runtime_error("Image is not a 32 bit architecture");

    //Check for PE32+ magic number
    if (this->ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        throw std::runtime_error("Image is not a 32 bit architecture");
    
    //Parse section headers to a vector
    for (int count = 0; count < ntHeaders->FileHeader.NumberOfSections; count++){
		this->sectionHeaders.push_back(PIMAGE_SECTION_HEADER(MINT(imageBaseAddr) + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (count * sizeof(IMAGE_SECTION_HEADER))));
	}
}

IMAGE_NT_HEADERS32* CPeImage32::getNTHeaders(){
    if(!imageWasParsed)
        throw std::runtime_error("Image was not parsed yet");
    return ntHeaders;
}

CPeImage64::CPeImage64() : CPeImage()
{
}

CPeImage64::~CPeImage64()
{
}


void CPeImage64::parseImage()
{
    this->ntHeaders = this->dosHeader->e_lfanew + (IMAGE_NT_HEADERS64*)this->imageBaseAddr; 
    
    
    if (this->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Image doesn't have the PE format IMAGE_NT_SIGNATURE does not match");
    
    //Check for 64 bit architecture
    if (this->ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        throw std::runtime_error("Image is not a 64 bit architecture");

    //Check for PE32+ magic number
    if (this->ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error("Image is not a 64 bit architecture");

    //Parse section headers to a vector
    for (int count = 0; count < ntHeaders->FileHeader.NumberOfSections; count++){
		this->sectionHeaders.push_back(PIMAGE_SECTION_HEADER(MINT(imageBaseAddr) + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (count * sizeof(IMAGE_SECTION_HEADER))));
	}
}

IMAGE_NT_HEADERS64* CPeImage64::getNTHeaders(){
    if(!imageWasParsed)
        throw std::runtime_error("Image was not parsed yet");
    return ntHeaders;
}