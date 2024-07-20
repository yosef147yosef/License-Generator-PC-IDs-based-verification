#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "Mode.h"

/**
 * @file PEFormat.h
 * @brief Defines the PEFormat struct for handling Portable Executable (PE) files.
 *
 * This file provides the definition of the PEFormat struct, which encapsulates
 * the details of a PE file and provides methods to read the file, process
 * relocation entries, and retrieve addresses within a specified block.
 *
 * @autor Yosef Halevi
 */

 /**
  * @struct PEFormat
  * @brief Represents the Portable Executable (PE) file format and provides methods for processing relocation entries.
  *
  * This structure encapsulates the details of a PE file and provides methods to read the file,
  * process relocation entries, and retrieve addresses within a specified block.
  */
struct PEFormat {
    HANDLE hFile;                     ///< Handle to the PE file.
    DWORD fileSize;                   ///< Size of the PE file.
    BYTE* buffer;                     ///< Buffer to store the content of the PE file.
    PIMAGE_DOS_HEADER dosHeader;      ///< Pointer to the DOS header of the PE file.
#ifdef _MODE64
    PIMAGE_NT_HEADERS64 ntHeaders;    ///< Pointer to the NT headers (64-bit) of the PE file.
#else
    PIMAGE_NT_HEADERS32 ntHeaders;    ///< Pointer to the NT headers (32-bit) of the PE file.
#endif
    PIMAGE_SECTION_HEADER sectionHeader; ///< Pointer to the section headers of the PE file.
    PIMAGE_BASE_RELOCATION relocation;  ///< Pointer to the relocation table of the PE file.
    ADDR_TYPE relocRVA;                ///< Relative Virtual Address (RVA) of the relocation table.
    DWORD relocSize;                   ///< Size of the relocation table.
    ADDR_TYPE imageBase;               ///< Base address of the image.
    std::vector<ADDR_TYPE> relocationAddresses; ///< Vector of relocation addresses.

    ADDR_TYPE dataStartAddress;        ///< Start address of the .data section (relative to image base)
    ADDR_TYPE dataEndAddress;          ///< End address of the .data section (relative to image base)
    ADDR_TYPE rdataStartAddress;       ///< Start address of the .rdata section (relative to image base)
    ADDR_TYPE rdataEndAddress;         ///< End address of the .rdata section (relative to image base)

    /**
     * @brief Default constructor initializes member variables.
     */
    PEFormat();

    /**
     * @brief Constructs the PEFormat object and initializes it by reading the specified PE file.
     *
     * @param fileName Name of the PE file to read.
     */
    PEFormat(const char* fileName);

    /**
     * @brief Copy constructor for deep copying PEFormat objects.
     *
     * @param other The PEFormat object to copy from.
     */
    PEFormat(const PEFormat& other);

    /**
     * @brief Destructor to clean up allocated resources.
     */
    ~PEFormat();

    /**
     * @brief Processes the relocation entries in the PE file and stores them in the relocationAddresses vector.
     */
    void ProcessRelocationEntries();

    /**
     * @brief Retrieves addresses within a specified block.
     *
     * @param startAddress The start address of the block.
     * @param blockSize The size of the block.
     * @param addressesInBlock A vector to store the addresses found within the block.
     */
    void AddressesInBlock(ADDR_TYPE startAddress, size_t blockSize, std::vector<ADDR_TYPE>& addressesInBlock);
    ADDR_TYPE AddressInBlock(ADDR_TYPE startAddress, size_t blockSize);
};

/**
 * @brief Default constructor initializes member variables.
 */
PEFormat::PEFormat() : hFile(INVALID_HANDLE_VALUE), fileSize(0), buffer(NULL),
dosHeader(NULL), ntHeaders(NULL), sectionHeader(NULL),
relocation(NULL), relocRVA(0), relocSize(0), imageBase(0),
dataStartAddress(0), dataEndAddress(0), rdataStartAddress(0), rdataEndAddress(0) {}

/**
 * @brief Constructs the PEFormat object and initializes it by reading the specified PE file.
 *
 * @param fileName Name of the PE file to read.
 */
PEFormat::PEFormat(const char* fileName) {
    hFile = INVALID_HANDLE_VALUE;
    fileSize = 0;
    buffer = NULL;
    dosHeader = NULL;
    ntHeaders = NULL;
    sectionHeader = NULL;
    relocation = NULL;
    relocRVA = 0;
    relocSize = 0;
    imageBase = 0;
    dataStartAddress = 0;
    dataEndAddress = 0;
    rdataStartAddress = 0;
    rdataEndAddress = 0;

    DWORD bytesRead = 0;

    hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file. Error: %d\n", GetLastError());
        return;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Could not get file size. Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    buffer = (BYTE*)malloc(fileSize);
    if (buffer == NULL) {
        printf("Could not allocate memory\n");
        hFile = INVALID_HANDLE_VALUE;
        CloseHandle(hFile);
        return;
    }

    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Could not read file. Error: %d\n", GetLastError());
        buffer = NULL;
        hFile = INVALID_HANDLE_VALUE;
        free(buffer);
        CloseHandle(hFile);
        return;
    }

    dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        buffer = NULL;
        hFile = INVALID_HANDLE_VALUE;
        free(buffer);
        CloseHandle(hFile);
        return;
    }

#ifdef _MODE64
    ntHeaders = (PIMAGE_NT_HEADERS64)(buffer + dosHeader->e_lfanew);
#else
    ntHeaders = (PIMAGE_NT_HEADERS32)(buffer + dosHeader->e_lfanew);
#endif

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        buffer = NULL;
        hFile = INVALID_HANDLE_VALUE;
        free(buffer);
        CloseHandle(hFile);
        return;
    }

#ifdef _MODE64
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("Not a 64-bit executable\n");
        buffer = NULL;
        hFile = INVALID_HANDLE_VALUE;
        free(buffer);
        CloseHandle(hFile);
        return;
    }
#else
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("Not a 32-bit executable\n");
        buffer = NULL;
        hFile = INVALID_HANDLE_VALUE;
        free(buffer);
        CloseHandle(hFile);
        return;
    }
#endif

    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    imageBase = ntHeaders->OptionalHeader.ImageBase;

    // Find .data and .rdata sections
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader[i].Name, ".data") == 0) {
            dataStartAddress = sectionHeader[i].VirtualAddress - imageBase;
            dataEndAddress = dataStartAddress + sectionHeader[i].Misc.VirtualSize;
        }
        else if (strcmp((char*)sectionHeader[i].Name, ".rdata") == 0) {
            rdataStartAddress = sectionHeader[i].VirtualAddress - imageBase;
            rdataEndAddress = rdataStartAddress + sectionHeader[i].Misc.VirtualSize;
        }
    }

    if (relocRVA != 0 && relocSize > 0) {
        DWORD relocOffset = 0;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (relocRVA >= sectionHeader[i].VirtualAddress &&
                relocRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
                relocOffset = relocRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
                break;
            }
        }
        if (relocOffset != 0) {
            relocation = (PIMAGE_BASE_RELOCATION)(buffer + relocOffset);
            ProcessRelocationEntries();
        }
    }
}

/**
 * @brief Copy constructor for deep copying PEFormat objects.
 *
 * @param other The PEFormat object to copy from.
 */
PEFormat::PEFormat(const PEFormat& other) {
    hFile = INVALID_HANDLE_VALUE;  // We don't copy the file handle
    fileSize = other.fileSize;

    if (other.buffer != NULL) {
        buffer = (BYTE*)malloc(fileSize);
        if (buffer != NULL) {
            memcpy(buffer, other.buffer, fileSize);
            dosHeader = (PIMAGE_DOS_HEADER)buffer;
            ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
            sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

            DWORD relocOffset = (BYTE*)other.relocation - other.buffer;
            relocation = (PIMAGE_BASE_RELOCATION)(buffer + relocOffset);
        }
    }
    else {
        buffer = NULL;
        dosHeader = NULL;
        ntHeaders = NULL;
        sectionHeader = NULL;
        relocation = NULL;
    }

    relocRVA = other.relocRVA;
    relocSize = other.relocSize;
    imageBase = other.imageBase;
    relocationAddresses = other.relocationAddresses;

    dataStartAddress = other.dataStartAddress;
    dataEndAddress = other.dataEndAddress;
    rdataStartAddress = other.rdataStartAddress;
    rdataEndAddress = other.rdataEndAddress;
}

/**
 * @brief Destructor to clean up allocated resources.
 */
PEFormat::~PEFormat() {
    if (buffer != NULL) {
        free(buffer);
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}

/**
 * @brief Processes the relocation entries in the PE file and stores them in the relocationAddresses vector.
 */
void PEFormat::ProcessRelocationEntries() {
    DWORD remainingSize = relocSize;
    PIMAGE_BASE_RELOCATION currentRelocation = relocation;

    while (remainingSize > 0) {
        DWORD blockSize = currentRelocation->SizeOfBlock;
        DWORD entriesCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)currentRelocation + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entriesCount; i++) {
            WORD entry = entries[i];
            DWORD type = entry >> 12;
            DWORD offset = entry & 0xFFF;

            if (type != 0) { // Type 0 means padding
                ADDR_TYPE relocAddress = currentRelocation->VirtualAddress + offset;
                relocationAddresses.push_back(relocAddress);
            }
        }

        remainingSize -= blockSize;
        currentRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)currentRelocation + blockSize);
    }
}

/**
 * @brief Retrieves addresses within a specified block.
 *
 * @param startAddress The start address of the block.
 * @param blockSize The size of the block.
 * @param addressesInBlock A vector to store the addresses found within the block.
 */
void PEFormat::AddressesInBlock(ADDR_TYPE startAddress, size_t blockSize, std::vector<ADDR_TYPE>& addressesInBlock) {
    ADDR_TYPE endAddress = startAddress + blockSize;

    for (const auto& address : relocationAddresses) {
        if (address >= startAddress && address < endAddress) {
            addressesInBlock.push_back(address);
        }
    }
}

ADDR_TYPE PEFormat::AddressInBlock(ADDR_TYPE startAddress, size_t blockSize) {
    ADDR_TYPE endAddress = startAddress + blockSize;

    for (const auto& address : relocationAddresses) {
        if (address >= startAddress && address < endAddress) {
            return address;
        }
    }
    return NULL;
}