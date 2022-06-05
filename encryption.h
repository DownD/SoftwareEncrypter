#pragma once
#include <iostream>
#include <string>

const char* key = "ISYDF786jkh1324sdfsSJKLDF"; //Any chars will work
int key_len = strlen(key);

// XOR Encryption
void encryptDecrypt(std::string toEncrypt) {


    for (int i = 0; i < toEncrypt.size(); i++)
        toEncrypt[i] = toEncrypt[i] ^ key[i % (key_len / sizeof(char))];


}

void encryptDecrypt(std::vector<char>& toEncrypt) {

    for (int i = 0; i < toEncrypt.size(); i++)
        toEncrypt[i] = toEncrypt[i] ^ key[i % (key_len / sizeof(char))];

}