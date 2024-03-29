# Simple Crypter
This a PoC for education purposes only to explore the techniques known as Process Hollowing, RunPE and Process Doppelganging.

It builds a stub program with an encrypted payload. Once this stub is ran, it will decrypt the data in-memory and spawn a new process of itself and replace the image with the payload, for a better overview of this check out this article ([Runtime-Crypter](https://www.codeproject.com/Articles/1174823/Cplusplus-Runtime-Crypter)).

These techniques are very frequent for hiding malicious code and also for preventing reverse engineering.

# Structure
- Builder - The binary that will encrypt the payload.
- Stub - The binary that will be merged with the encrypted payload as a resource.
- build_64.bat - Script that is responsible for building the encrypted payload and embed it into the Stub. 

# How it works
- *Builder.exe*\
The Builder.exe is responsible for taking a payload and encrypt with XOR encryption.\
To do this just run Builder.exe and follow the steps, it also supports 2 additional arguments (path of the payload, final path of the encrypted payload).
ATTENTION: This program just encrypts the entire binary, you won't be able to run the produced file, that will be the job of the Stub.exe.
  - Example: ```Builder.exe .\payload.exe .\encrypted_payload.exe```

- *Stub.exe*\
This is the final binary that will be build using the encrypted payload as resource file and later on decrypting the payload in memory and use the technique called "Process Hollowing" to run a new process with the payload.\
It uses a variant Processing Hollowing, it creates another process, copy of itself in suspended mode, map's the encrypted file without unmapping the original, finally it load's a shellcode to fix relocations/imports and redirects the entry point to the mapped payload by patching the PEB ImageBase and the entryPoint of the context.\
The shellcode is executed by writing it to the target process and creating a remote new thread while the process is suspended.

  - build_64.bat\
Since the Stub.exe needs to be build every time, this script takes care of encrypting the payload (using Builder.exe) and building the Stub project outputing the final binary.


# How to run
From the visual studio developer tools console run the build_64.bat.
It takes at least one argument, the payload location, and an additional optional argument, the target location of the stub binary.
Examples:
- ```build_64.bat .\payload.exe .\runpe_payload.exe```
- ```build_64.bat .\payload.exe``` (In this case the final binary will be in ./tmp/encrypted_binary.exe)

# Dependencies
vcpkg install minhook:x64-windows-static

# Resources
https://www.codeproject.com/Articles/1174823/Cplusplus-Runtime-Crypter
https://github.com/codecrack3/Run-PE---Run-Portable-Executable-From-Memory/blob/master/RunPE.cpp
https://gist.github.com/valinet/e27e64927db330b808c3a714c5165b0a
https://github.com/hasherezade/transacted_hollowing#ghostly-hollowing

# TODO
- Apply proper protection to the sections and headers
- Attempt to redirect the entry point to avoid using a new thread, or apply without shellcode
- Attempt to patch the PEB to the older value
