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
bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, HANDLE hprocess, BYTE* key, PEFormat& file_fields, ADDR_TYPE currentEip, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE>& breakpoints_address_map)
{
    std::vector<ADDR_TYPE> addr_to_reallocate_in_the_block;
    file_fields.AddressesInBlock(currentEip, block_size, addr_to_reallocate_in_the_block);
    ADDR_TYPE reallocate_factor = file_fields.imageBase - base_address;
    for (const auto& addr : addr_to_reallocate_in_the_block)
    {
        if (!reallocateAddress(addr, hprocess, reallocate_factor))
            return false;
    }
    printf("the addres is %p \n", start_address + file_fields.imageBase);
    printf("the end address is %p \n", breakpoints_address_map[start_address]  + file_fields.imageBase);
    if (!encrypt_block(currentEip, block_size, hprocess, key))
    {
        printf("ERROR couldn't decrypt the block starting at %p correctly\n", (LPVOID)currentEip);
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
bool encrypt_block_with_realloction(ADDR_TYPE start_address, SIZE_T block_size, PROCESS_INFORMATION& pi, License license, PEFormat& file_fields, ADDR_TYPE currentEip, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE> breakpoints_address_map)
{
    if (!license.verifyLicense())
    {
        printf("ERROR! the license had being curated \n ");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        ExitProcess(NULL);
    }
    BYTE key[AES_KEY_LENGTH];
    gen_key(start_address - base_address, license, key);
    return encrypt_block_with_realloction(start_address, block_size, pi.hProcess, key, file_fields, currentEip, base_address, breakpoints_address_map);

}
bool enc_part_of_block(PROCESS_INFORMATION pi, ADDR_TYPE cur_virtual_address, BYTE key[], PEFormat& file_fields, ADDR_TYPE currentEip, ADDR_TYPE base_address, std::map<ADDR_TYPE, ADDR_TYPE> breakpoints_address_map)
{
    for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it)
    {
        if (cur_virtual_address > it->first and cur_virtual_address < it->second)
        {
            if (!encrypt_block_with_realloction(cur_virtual_address, it->second - it->first, pi, key, file_fields, currentEip, base_address, breakpoints_address_map))
            {
                printf("ERROR coundl decrypt %p ", cur_virtual_address + file_fields.imageBase);
                return false;
            }
            return true;
        }
    }
    return false;
}
