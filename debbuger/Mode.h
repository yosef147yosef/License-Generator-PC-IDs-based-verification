#pragma once
#define MAX_ADDRESSES 100000
#define _MODE_64  false
#if _MODE_64==true
typedef DWORD64 ADDR_TYPE;
#else
typedef DWORD ADDR_TYPE;
#endif
#define MAX_BREAKPOINTS 100000
//#define EXE_FILE_NAME  "C:\\Users\\Windows10\\PycharmProjects\\LicenseEncriptino\\example.exe_out.exe"
#define EXE_FILE_NAME  "C:\\Users\\Windows10\\Desktop\\SofwareToDemostrate\\Debug\\SofwareToDemostrate.exe_out.exe"
//#define BLOCKS_FILE_NAME "C:\\Users\\Windows10\\PycharmProjects\\LicenseEncriptino\\blocks_list.bin"
#define BLOCKS_FILE_NAME "C:\\Users\\Windows10\\Desktop\\SofwareToDemostrate\\Debug\\blocks_list.bin"
//#define CALLS_ADDRESS_FILE_Name "C:\\Users\\Windows10\\PycharmProjects\\LicenseEncriptino\\call_address_list.bin"
#define CALLS_ADDRESS_FILE_Name "C:\\Users\\Windows10\\Desktop\\SofwareToDemostrate\\Debug\\call_address_list.bin"
#define SIZE_HASHED 65
#define SIZE_64 64
#define AES_KEY_LENGTH 16
#define SIGNATURE_LENGTH 32
#define CONCATENATE_SIZE 16
#define RSA_KEY_LENGTH 512
#define PUBLIC_KEY_FILENAME "public.pem"
#define PRIVATE_KEY_FILENAME "private.pem"
#define LICENSE_FILENAME "License.dat"
#include <openssl/rsa.h>
#include <openssl/evp.h>


