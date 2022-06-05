#include <stdio.h>
#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include "..\encryption.h"

#define PRINT_INFO(...) printf(__VA_ARGS__); printf("\n");fflush(stdout);
#define PRINT_ERROR(...) printf("[ERROR]"); printf(__VA_ARGS__); printf("%d\n",GetLastError());fflush(stdout);

//Reads and allocates memory from a binary file
//Buffer will be cleared if it has anything
bool readBinary(std::vector<char>* buffer, std::string fileName) {
    std::ifstream file(fileName, std::ios::binary | std::ios::ate);

    if (file.is_open()) {

        // File size
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        //Reserves memory
        buffer->clear();
        buffer->resize(size);

        //Attempt to read file
        if (file.read(buffer->data(), size))
        {
            file.close();
            return true;
        }

        PRINT_ERROR("Error reading file %s",fileName.c_str());
        file.close();
        return false;

    }

    PRINT_ERROR("Error opening file %s", fileName.c_str());
    return false;
}



bool encryptDecryptFile(std::string payloadName, bool encrypt, std::string fileName = "") {
    std::vector<char> payloadBuffer;
    std::string new_file_name;

    if (!readBinary(&payloadBuffer, payloadName)) {
        return 0;
    }

    PRINT_INFO("%d bytes read", payloadBuffer.size());

    //Encrypt or decrypt payload
    encryptDecrypt(payloadBuffer);

    //Create new file
    if (encrypt)
        new_file_name = ENCRYPTED_BINARY_PATH;
    else
        new_file_name = DECRYPTED_BINARY_PATH;

    //Check if target file path is provided
    if (fileName != "")
        new_file_name = fileName;

    std::fstream encrypted_file(new_file_name, std::ios::out | std::ios::binary);
    if (!encrypted_file.is_open())
    {
        PRINT_ERROR("Error creating new file at %s", new_file_name.c_str());
        return 0;
    }

    // Write data
    encrypted_file.write((char*)payloadBuffer.data(), payloadBuffer.size());
    encrypted_file.close();

    // Output success message
    if (encrypt){PRINT_INFO("%d bytes sucessfully encrypted to: %s", payloadBuffer.size(), new_file_name.c_str());}
    else { PRINT_INFO("%d bytes sucessfully decrypted to: %s", payloadBuffer.size(), new_file_name.c_str()); }

    fflush(stdin);
    return 1;
}

int main(int argc, const char** argv)
{
    //Attempt to read from arguments
    if (argc > 2) {
        std::string payloadName = argv[1];
        std::string resultName = argv[2];
        return !encryptDecryptFile(payloadName, 1, resultName);
    }
    std::cout << "Choose one\n";
    std::cout << "0 - Decrypt file\n";
    std::cout << "1 - Encrypt file\n";

    int choice = 0;
    std::cin >> choice;
    fflush(stdin);

    //Read input
    std::cout << "\nProvide the path of the file:\n";

    std::string payloadName;
    std::cin >> payloadName;
    fflush(stdin);

    switch (choice) {
    case 0: 
        encryptDecryptFile(payloadName, 0);
        break;
    case 1:
        encryptDecryptFile(payloadName, 1);
        break;
    default:
        std::cout << "Type either 0 or 1\n";
        main(0,0);
    }
    return 0;
}