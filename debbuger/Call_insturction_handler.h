#pragma once
#include "Mode.h"
#include <Windows.h>
#include <stdio.h>
#if  _MODE_64 == true
enum class Register64 {
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    UNKNOWN
};

Register64 identify_call_register(HANDLE hProcess, ADDR_TYPE instruction_addr) {
    BYTE instruction_bytes[3]; // Potentially need 3 bytes for REX prefix
    SIZE_T readByte;
    if (!ReadProcessMemory(hProcess, (LPVOID)instruction_addr, (LPVOID)instruction_bytes, 3, &readByte))
    {
        printf("ERROR reading the address %p \n", instruction_addr);
        return Register64::UNKNOWN;
    }

    int offset = 0;
    bool rex_w = false;

    // Check for REX prefix
    if ((instruction_bytes[0] & 0xF0) == 0x40) {
        rex_w = (instruction_bytes[0] & 0x08) != 0;
        offset = 1;
    }

    // Ensure we have a "call register" instruction
    if (instruction_bytes[offset] != 0xFF) {
        return Register64::UNKNOWN;
    }

    BYTE modrm = instruction_bytes[offset + 1];
    // Verify that this is indeed a "call register" instruction
    if ((modrm & 0xF8) != 0xD0) {
        return Register64::UNKNOWN;
    }

    // Extract the register code from the last 3 bits of the ModR/M byte
    BYTE reg_code = modrm & 0x07;

    // Adjust reg_code if REX.B is set
    if (offset == 1 && (instruction_bytes[0] & 0x01)) {
        reg_code |= 0x08;
    }

    // Map the register code to the enum value
    switch (reg_code) {
    case 0: return Register64::RAX;
    case 1: return Register64::RCX;
    case 2: return Register64::RDX;
    case 3: return Register64::RBX;
    case 4: return Register64::RSP;
    case 5: return Register64::RBP;
    case 6: return Register64::RSI;
    case 7: return Register64::RDI;
    case 8: return Register64::R8;
    case 9: return Register64::R9;
    case 10: return Register64::R10;
    case 11: return Register64::R11;
    case 12: return Register64::R12;
    case 13: return Register64::R13;
    case 14: return Register64::R14;
    case 15: return Register64::R15;
    default: return Register64::UNKNOWN; // This should never happen
    }
}
#else
enum class Register32 {
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    UNKNOWN
};

Register32 identify_call_register(HANDLE hProcess,ADDR_TYPE instruction_addr ) {
    BYTE instruction_bytes[2];
    SIZE_T readByte;
    if (!ReadProcessMemory(hProcess, (LPVOID)instruction_addr, (LPVOID)instruction_bytes, 2, &readByte))
    {
        printf("ERROR reading the address %p \n", instruction_addr);
        return Register32::UNKNOWN;
    }
    // Ensure we have a "call register" instruction
    if (instruction_bytes[0] != 0xFF) {
        return Register32::UNKNOWN;
    }

    BYTE modrm = instruction_bytes[1];
    // Verify that this is indeed a "call register" instruction
    if ((modrm & 0xF8) != 0xD0) {
        return Register32::UNKNOWN;
    }

    // Extract the register code from the last 3 bits of the ModR/M byte
    BYTE reg_code = modrm & 0x07;

    // Map the register code to the enum value
    switch (reg_code) {
    case 0: return Register32::EAX;
    case 1: return Register32::ECX;
    case 2: return Register32::EDX;
    case 3: return Register32::EBX;
    case 4: return Register32::ESP;
    case 5: return Register32::EBP;
    case 6: return Register32::ESI;
    case 7: return Register32::EDI;
    default: return Register32::UNKNOWN; // This should never happen
    }
}
#endif
void read_call_addresses_from_binary(const char* filename, std::vector<ADDR_TYPE>& addresses) {
    FILE* file;
    errno_t err;

    fopen_s(&file, filename, "rb");
    if (!file) {
        printf("Failed to open file: %s \n", filename);
        return;
    }
    ADDR_TYPE cur_address = NULL;
    while (addresses.size() < MAX_ADDRESSES &&
        fread(&cur_address, sizeof(ADDR_TYPE), 1, file) == 1) {
        addresses.push_back(cur_address);

    }
    fclose(file);
}
