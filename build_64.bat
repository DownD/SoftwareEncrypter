
@echo off
SET unencrypted_file=%1


:: Check arguments
IF "%1" == "" echo First argument needs to be the path of the binary to be encrypted && goto :error

IF "%2" == "" (SET crypted_file=".\tmp\encrypted_binary.exe") ELSE (SET crypted_file=%2)


:: Encrypt payload
.\x64\Release\Builder.exe %unencrypted_file% .\tmp\crypted.exe || echo Error encrypting file &&  goto :error

:: Build stub - Make sure to build with develoepr command tools of visual studio
msbuild Crypter.sln /t:Stub /p:Configuration="Release" /p:Platform="x64" || echo Error building project && goto :error

:: Copy to destination directory
move .\x64\Release\Stub.exe %crypted_file%  || echo Error encrypted stub && goto :error
:: del .\tmp\crypted.exe  || echo "Error deleting temporary files"

echo Success the final binary has been placed at %crypted_file%




:error
