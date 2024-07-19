#pragma once
#include "Mode.h"
#include "Get_Reallocations.h"
#include <vector>
#include "Key_Gen.h"
#include "License.h"
#include <windows.h>
#include <psapi.h>
unsigned char iv[] = { 0xc2, 0x40, 0xec, 0xd0, 0x63, 0x63, 0x62, 0xdf, 0xbf, 0xd3, 0xb8, 0xf2, 0x7c, 0x3b, 0x80, 0x02, 0x90 };
void read_block_addresses_from_binary(const char* filename, std::map<ADDR_TYPE, ADDR_TYPE>& addresses) {
    FILE* file;
    errno_t err;

    err = fopen_s(&file, filename, "rb");
    if (err != 0) {
        printf("Failed to open file: %s \n", filename);
        return;
    }

    ADDR_TYPE address_pair[2];
    size_t read_count;

    while (addresses.size() < MAX_ADDRESSES &&
        fread(address_pair, sizeof(ADDR_TYPE), 2, file) == 2) {
        addresses[address_pair[0]] = address_pair[1];
    }

    fclose(file);
}

void print_byte_array_as_hex(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", array[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


bool aes_ctr_encrypt(BYTE* plaintext, BYTE* key, BYTE* iv, BYTE* ciphertext, SIZE_T size) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return false;
    }

    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Perform encryption
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, size)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}



ADDR_TYPE get_process_base_address(HANDLE hProcess) {
    ADDR_TYPE baseAddress = NULL;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    DWORD flags = LIST_MODULES_DEFAULT;

#ifdef _MODE64
    // For 64-bit processes
    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_64BIT)) {
        DWORD error = GetLastError();
        SetLastError(error);
        return NULL;
    }
#else
    // For 32-bit processes
    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded , LIST_MODULES_32BIT)) {
        DWORD error = GetLastError();
        SetLastError(error);
        return NULL;
    }
#endif

    // The first module in the array is the executable
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
        DWORD error = GetLastError();
        SetLastError(error);
        return NULL;
    }

    baseAddress = (ADDR_TYPE)modInfo.lpBaseOfDll;
    return baseAddress;
}





