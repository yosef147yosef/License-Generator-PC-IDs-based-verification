#pragma once
#include "Mode.h"
#include "Raw_Bytes_Helper.h"
#include "Debbuger.h"
#include "Get_Reallocations.h"
#include <vector>
#include "Key_Gen.h"
#include "License.h"
#include <windows.h>
#include <psapi.h>

/**
 * @brief Encrypts a block of memory in the target process.
 *
 * @param start_address Starting address of the block to encrypt.
 * @param size Size of the block to encrypt.
 * @param hprocess Handle to the target process.
 * @param key Encryption key.
 * @return true if encryption was successful, false otherwise.
 */
bool encrypt_block(ADDR_TYPE start_address, SIZE_T size, HANDLE hprocess, BYTE* key)
{
    BYTE* cypher = (BYTE*)malloc(size);
    if (cypher == NULL) {
        printf("Memory allocation failed for cypher\n");
        return false;
    }
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


/**
 * @brief Reallocates an address in the target process.
 *
 * @param addr Address to reallocate.
 * @param hprocess Handle to the target process.
 * @param reallocate_factor Factor by which to reallocate the address.
 * @param size Size of the address (default is sizeof(ADDR_TYPE)).
 * @return true if reallocation was successful, false otherwise.
 */
bool reallocateAddress(ADDR_TYPE addr, HANDLE hprocess, ADDR_TYPE reallocate_factor , SIZE_T size = sizeof(ADDR_TYPE))
{
    ADDR_TYPE tempBuffer; // Assuming DWORD is the size to read, adjust as needed
    SIZE_T bytesRead;
    if (ReadProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, size, &bytesRead)) {
        // Append read bytes to the buffer
        tempBuffer += reallocate_factor;
        if (!WriteProcessMemory(hprocess, (LPVOID)addr, &tempBuffer, size, &bytesRead))
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


/**
 * @brief Gets the start address of a block containing the given virtual address.
 *
 * @param cur_virtual_address Current virtual address.
 * @param breakpoints_address_map Map of breakpoint addresses.
 * @return Start address of the block, or NULL if not found.
 */
ADDR_TYPE get_start_block(ADDR_TYPE cur_virtual_address, std::map<ADDR_TYPE,ADDR_TYPE>& breakpoints_address_map)
{
    for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it)
    {
        if (cur_virtual_address > it->first and cur_virtual_address < it->second)
        {
            return it->first;
        }
    }
    return NULL;
}

/**
 * @brief Encrypts a block with reallocation in the target process.
 *
 * @param start_address Starting address of the block.
 * @param block_size Size of the block.
 * @param hprocess Handle to the target process.
 * @param key Encryption key.
 * @param file_fields PEFormat object containing file information.
 * @param base_address Base address of the process.
 * @param breakpoints_address_map Map of breakpoint addresses.
 * @return true if encryption and reallocation were successful, false otherwise.
 */
bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, HANDLE hprocess, BYTE* key, PEFormat& file_fields, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE>& breakpoints_address_map)
{
    std::vector<ADDR_TYPE> addr_to_reallocate_in_the_block;
    file_fields.AddressesInBlock(start_address+base_address, block_size, addr_to_reallocate_in_the_block);
    ADDR_TYPE reallocate_factor = file_fields.imageBase - base_address;
    for (const auto& addr : addr_to_reallocate_in_the_block)
    {
        if (!reallocateAddress(addr, hprocess, reallocate_factor))
            return false;
    }
    printf("the addres is %p \n", start_address + file_fields.imageBase);
    printf("the end address is %p \n", breakpoints_address_map[start_address]  + file_fields.imageBase);
    if (!encrypt_block(start_address+ base_address, block_size, hprocess, key))
    {
        printf("ERROR couldn't decrypt the block starting at %p correctly\n", (LPVOID)(start_address + base_address));
        return false;
    }
    for (const auto& addr : addr_to_reallocate_in_the_block)
    {
        printf("address to reallocated %p \n", addr-base_address+file_fields.imageBase);
        if (!reallocateAddress(addr, hprocess, -1 * reallocate_factor))
            return false;
        ADDR_TYPE addr_being_allocated;
        SIZE_T read;
        if (!ReadProcessMemory(hprocess, (LPVOID)addr, &addr_being_allocated, sizeof(ADDR_TYPE), &read))
        {
            printf("EEROR reading from the address %p \n", addr);
        }
        addr_being_allocated -= base_address;
        for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it)
        {
            if (addr_being_allocated > it->first and addr_being_allocated < it->second)
            {
                if (!encrypt_block(it->first+base_address,it->second-it->first,hprocess,key))
                {
                    printf("couldnt decrypt the block starting from  %p", it->first);
                    return false;
                }
                break;
            }
        }
    }

    return true;
}

/**
 * @brief Encrypts a block with reallocation in the target process, using a license.
 *
 * @param start_address Starting address of the block.
 * @param block_size Size of the block.
 * @param pi Process information.
 * @param license License object for verification.
 * @param file_fields PEFormat object containing file information.
 * @param base_address Base address of the process.
 * @param breakpoints_address_map Map of breakpoint addresses.
 * @return true if encryption and reallocation were successful, false otherwise.
 */
bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, PROCESS_INFORMATION& pi, License license, PEFormat& file_fields, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE>& breakpoints_address_map)
{
    if (!license.verifyLicense())
    {
        printf("ERROR! the license had being curated \n ");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ExitProcess(NULL);
    }
    BYTE key[AES_KEY_LENGTH];
    gen_key(start_address, license, key);
    return encrypt_block_with_realloction(start_address, block_size, pi.hProcess, key, file_fields,  base_address, breakpoints_address_map);

}


/**
 * @brief Encrypts part of a block in the target process.
 *
 * @param pi Process information.
 * @param cur_virtual_address Current virtual address.
 * @param key Encryption key.
 * @param file_fields PEFormat object containing file information.
 * @param base_address Base address of the process.
 * @param breakpoints_address_map Map of breakpoint addresses.
 * @return true if encryption was successful, false otherwise.
 */
bool enc_part_of_block(PROCESS_INFORMATION pi, ADDR_TYPE cur_virtual_address, BYTE key[], PEFormat& file_fields, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE> breakpoints_address_map)
{
    for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it)
    {
        if (cur_virtual_address > it->first and cur_virtual_address < it->second)
        {
            if (!encrypt_block_with_realloction(it->first, it->second - it->first, pi, key, file_fields, base_address, breakpoints_address_map))
            {
                printf("ERROR coundl decrypt %p ", cur_virtual_address + file_fields.imageBase);
                return false;
            }
            return true;
        }
    }
    return false;
}

/**
 * @brief Encrypts data and rdata sections in the target process.
 *
 * @param file_fields PEFormat object containing file information.
 * @param pi Process information.
 * @param base_address Base address of the process.
 * @param license License object for verification.
 * @return true if encryption was successful, false otherwise.
 */
bool enc_data_rdata_sections( PEFormat& file_fields, PROCESS_INFORMATION& pi,ADDR_TYPE base_address, License license)
{
    ADDR_TYPE data_section_start = file_fields.dataStartAddress;
    SIZE_T data_section_end = file_fields.dataEndAddress;
    ADDR_TYPE rdata_section_start = file_fields.rdataStartAddress;
    SIZE_T rdata_section_end = file_fields.rdataEndAddress;
    ADDR_TYPE reallocate_factor = file_fields.imageBase - base_address;
    for (ADDR_TYPE addr : file_fields.relocationAddresses)
    {
        if (addr >= data_section_start and addr < data_section_end or addr >= rdata_section_start and addr < rdata_section_end)
        {
            if (!reallocateAddress(addr, pi.hProcess, reallocate_factor))
            {
                printf("ERROR couldnt reallocate the address %p \n", addr);
                return false;
            }
        }
    }
    if (!license.verifyLicense())
    {
        printf("ERROR! the license had being curated \n ");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ExitProcess(NULL);
    }
    BYTE data_key[AES_KEY_LENGTH];
    gen_key(data_section_start, license, data_key);   
    BYTE rdata_key[AES_KEY_LENGTH];
    gen_key(data_section_start, license, rdata_key);
    if (!encrypt_block(data_section_start + base_address, data_section_end - data_section_start, pi.hProcess, rdata_key)|| encrypt_block(data_section_start + base_address, data_section_end - data_section_start, pi.hProcess, data_key))
    {
        printf("ERROR decrypting data or rdata sections\n ");
        return false;
    }
    return true;
}
