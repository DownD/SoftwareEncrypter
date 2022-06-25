#pragma once
#include <Windows.h>
#include <vector>
class CPeImage
{
public:

    //Constructor
    CPeImage();
    ~CPeImage();

    //Responsible for parsing DOS header
    void parseBaseImage(void* imageBaseAddr, int size);
    IMAGE_DOS_HEADER* getDOSHeader();

protected:
    //Responsible for parsing NT headers and all architeture specific headers
    virtual void parseImage() = 0;

protected:
    void* imageBaseAddr;
    IMAGE_DOS_HEADER* dosHeader;
    int imageSize;
    bool imageWasParsed;
};



class CPeImage32 : public CPeImage
{
public:

    //Constructor
    CPeImage32();
    ~CPeImage32();

    IMAGE_NT_HEADERS32* getNTHeaders();

protected:
    void parseImage();

private:
    IMAGE_NT_HEADERS32* ntHeaders;
    std::vector<IMAGE_SECTION_HEADER*> sectionHeaders;
};

class CPeImage64 : public CPeImage
{
public:

    //Constructor
    CPeImage64();
    ~CPeImage64();

    //Get Image NT Headers
    IMAGE_NT_HEADERS64* getNTHeaders();

protected:
    void parseImage();

private:
    IMAGE_NT_HEADERS64* ntHeaders;
    std::vector<IMAGE_SECTION_HEADER*> sectionHeaders;
};

