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
#define CALLS_ADDRESS_FILE_Name "C:\\Users\\Windows10\Desktop\\SofwareToDemostrate\\Debug\\call_address_list.bin"
#define SIZE_INFO 16
#define SIZE_CPU_ID 32
#define SIZE_HASHED 65
#define SIZE_INT 128
#define SIZE_IDS_VARIABLE 128
#define AES_KEY_LENGTH 128
#define PC_ID_LENGTH 256
#define SIGNATURE_LENGTH 256
#define CONCATENATE_SIZE 1024
#define RSA_KEY_LENGTH 2048
#define PUBLIC_KEY_FILENAME "public.pem"
#define PRIVATE_KEY_FILENAME "private.pem"
#define LICENSE_FILENAME "License.dat"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>



