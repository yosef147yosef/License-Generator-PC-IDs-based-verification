#pragma once
#include "Mode.h"
#include "Get_Reallocations.h"
#include <vector>
#include "Key_Gen.h"
#include "License.h"
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

#include <windows.h>
#include <psapi.h>

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



bool encrypt_block(ADDR_TYPE start_address, SIZE_T size, HANDLE hprocess, BYTE* key)
{
    BYTE* cypher = (BYTE*)malloc(size);
    if (cypher == NULL) {
        printf("Memory allocation failed for cypher\n");
        return false;
    }
    unsigned char iv[] = { 0xc2, 0x40, 0xec, 0xd0, 0x63, 0x63, 0x62, 0xdf, 0xbf, 0xd3, 0xb8, 0xf2, 0x7c, 0x3b, 0x80, 0x02, 0x90 };
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hprocess, (LPVOID)start_address, cypher, size, &bytesRead))
    {
        printf("Can read from the address %p \n", (LPVOID)start_address);
        return false;
    }
    BYTE* plaintext = (BYTE*)malloc(size);
    if (!plaintext)
    {
        printf("ERROR could allocate memory for plaintext");
        return false;
    }
    aes_ctr_encrypt(cypher, key, iv, plaintext, size);
    if (!WriteProcessMemory(hprocess, (LPVOID)start_address, plaintext, size, &bytesRead))
    {
        printf("Can write to the address %p \n", (LPVOID)start_address);
        return false;
    }
    print_byte_array_as_hex(plaintext, size);
    print_byte_array_as_hex(cypher, size);
    printf("% p \n", start_address);
    free(cypher);
    free(plaintext);
    return true;
}
bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, HANDLE hprocess, BYTE* key ,  PEFormat& file_fields , ADDR_TYPE currentEip , ADDR_TYPE base_address)
{
    std::vector<ADDR_TYPE> addr_to_reallocate_in_the_block;
    file_fields.AddressesInBlock(currentEip, block_size, addr_to_reallocate_in_the_block);
    for (const auto& addr : addr_to_reallocate_in_the_block)
    {
        ADDR_TYPE tempBuffer; // Assuming DWORD is the size to read, adjust as needed
        SIZE_T bytesRead;
        if (ReadProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, sizeof(tempBuffer), &bytesRead)) {
            // Append read bytes to the buffer
            tempBuffer -= base_address - file_fields.imageBase;
            if (!WriteProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, sizeof(tempBuffer), &bytesRead))
            {
                printf("ERROR could write the reallocated address %p ", addr);
                return false;
            }
        }
        else {
            printf("ERROR could read the reallocated address %p ", addr);
            return false;
        }
    }
    if (!encrypt_block(currentEip, block_size, hprocess, key))
    {
        printf("ERROR couldn't decrypt the block starting at %p correctly\n", (LPVOID)currentEip);
        return false;
    }
    for (const auto& addr : addr_to_reallocate_in_the_block)
    {
        ADDR_TYPE tempBuffer; // Assuming DWORD is the size to read, adjust as needed
        SIZE_T bytesRead;
        if (ReadProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, sizeof(tempBuffer), &bytesRead)) {
            // Append read bytes to the buffer
            tempBuffer += base_address - file_fields.imageBase;
            if (!WriteProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, sizeof(tempBuffer), &bytesRead))
            {
                printf("ERROR could write the reallocated address %p ", addr);
                return false;
            }
        }
        else {
            printf("ERROR could read the reallocated address %p ", addr);
            return false;
        }
    }
    return true;
}

inline bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, PROCESS_INFORMATION& pi, License license, PEFormat& file_fields, ADDR_TYPE currentEip, ADDR_TYPE base_address)
{
    if (!license.verifyLicense())
    {
        printf("ERROR! the license had being curated \n ");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ExitProcess(NULL);
    }
    BYTE key[AES_KEY_LENGTH];
    gen_key(start_address-base_address, license, key);
    return encrypt_block_with_realloction(start_address, block_size, pi.hProcess,key , file_fields, currentEip, base_address);

}