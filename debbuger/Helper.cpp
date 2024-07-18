#pragma once
#include "Helper.h"
#include <iphlpapi.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#pragma comment(lib, "iphlpapi.lib")

/**
 * General Explanation for  FILE *pipe = _popen
 *
 * @brief Executes a command using the Windows Management Instrumentation Command-line (WMIC).
 *
 * Several functions in this file use the `popen` function to execute WMIC commands. The `popen` function
 * opens a process by creating a pipe, forking, and invoking the shell. It returns a pointer to a stream
 * that can be used to read the command's output.
 */

 /**
  * @brief Retrieves the disk UUID.
  *
  * This function executes a command to fetch the disk UUID using the Windows Management Instrumentation Command-line (WMIC).
  * The result is stored in the provided buffer.
  *
  * @param diskUUID The buffer to store the retrieved disk UUID.
  */
void GetDiskUUID(char* diskUUID)
{
    FILE* pipe = _popen("wmic csproduct get uuid", "r");
    if (!pipe)
    {
        perror("popen() failed!");
        return;
    }

    char buffer[SIZE_64];
    bool firstLine = true;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        if (firstLine)
        {
            firstLine = false;
            continue; // Skip the first line
        }
        strncat_s(diskUUID, SIZE_64, buffer, _TRUNCATE);
    }
    _pclose(pipe);

    // Clean up the output string
    diskUUID[strcspn(diskUUID, "\r\n")] = 0; // Remove newlines

    // Trim whitespace at the end of the string
    int i = (int)strlen(diskUUID) - 1;
    while (i >= 0 && isspace((unsigned char)diskUUID[i]))
    {
        diskUUID[i] = '\0';
        i--;
    }
}

/**
 * @brief Retrieves the MAC address of the machine.
 *
 * This function fetches the MAC address of the machine using the GetAdaptersInfo function from the IP Helper API.
 * The MAC address is stored in the provided buffer.
 *
 * @param MAC_address The buffer to store the retrieved MAC address.
 */
void GetMACAddress(char* MAC_address)
{
    IP_ADAPTER_INFO AdapterInfo[SIZE_64];             // Allocate information for up to 16 NICs
    DWORD dwBufLen = sizeof(AdapterInfo);                     // Save the size in dwBufLen
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen); // Call GetAdaptersInfo

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Contains pointer to current adapter info

    do
    {
        for (UINT i = 0; i < pAdapterInfo->AddressLength; i++)
        {
            sprintf_s(MAC_address + (i * 3), SIZE_64 - (i * 3), "%02x:", pAdapterInfo->Address[i]);
        }
        MAC_address[strlen(MAC_address) - 1] = '\0'; // Remove the last ':'
        pAdapterInfo = pAdapterInfo->Next;
    } while (pAdapterInfo);
}

/**
 * @brief Retrieves the volume serial number of the C: drive.
 *
 * This function calls GetVolumeInformation to fetch the serial number of the volume mounted at the current location.
 *
 * @param volumeSerialNumber A pointer to a DWORD to store the retrieved volume serial number.
 */
void getSerialNumber(DWORD* volumeSerialNumber)
{
    if (!GetVolumeInformation(NULL, NULL, 0, volumeSerialNumber, NULL, NULL, NULL, 0))
    {
        // Handle the error
        DWORD error = GetLastError();
        fprintf(stderr, "GetVolumeInformation failed with error code %lu\n", error);
    }
}

/**
 * @brief Retrieves the processor ID.
 *
 * This function uses the __cpuid intrinsic to get the processor ID and stores it in the provided buffer.
 *
 * @param cpuId The buffer to store the retrieved processor ID.
 */
void getProcessorId(char* cpuId)
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    sprintf_s(cpuId, SIGNATURE_LENGTH, "%08X%08X", cpuInfo[3], cpuInfo[0]);
}

/**
 * @brief Retrieves the motherboard ID.
 *
 * This function executes a command to fetch the motherboard serial number using the Windows Management Instrumentation Command-line (WMIC).
 * The result is stored in the provided buffer.
 *
 * @param motherboardID The buffer to store the retrieved motherboard ID.
 */
void GetMotherboardID(char* motherboardID)
{
    FILE* pipe = _popen("wmic baseboard get serialnumber", "r");
    if (!pipe)
    {
        perror("popen() failed!");
        return;
    }

    char buffer[SIZE_64];
    bool firstLine = true;
    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        if (firstLine)
        {
            firstLine = false;
            continue; // Skip the first line
        }
        strncat_s(motherboardID, SIZE_64, buffer, _TRUNCATE);
    }
    _pclose(pipe);

    // Clean up the output string
    motherboardID[strcspn(motherboardID, "\r\n")] = 0; // Remove newlines
}

/**
 * @brief Computes the SHA-256 hash of a given string.
 *
 * This function takes a string and computes its SHA-256 hash, storing the result in the provided buffer.
 *
 * @note The SHA256_DIGEST_LENGTH constant, defined by OpenSSL, specifies that the SHA-256 hash
 * has a length of 256 bits (32 bytes).
 *
 * @param hashedIDs The buffer to store the computed hash.
 * @param str The input string to hash.
 */
void sha256(unsigned char* hashedIDs, const char* str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx;

    // Initialize the SHA-256 context
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        perror("EVP_MD_CTX_new() failed!");
        return;
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    {
        perror("EVP_DigestInit_ex() failed!");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (1 != EVP_DigestUpdate(mdctx, str, strlen(str)))
    {
        perror("EVP_DigestUpdate() failed!");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL))
    {
        perror("EVP_DigestFinal_ex() failed!");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    // Copy the hash to the hashedIDs buffer
    memcpy_s(hashedIDs, SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH);
}

/**
 * @brief Converts a hash value to a hexadecimal string.
 *
 * This function converts a hash value (array of bytes) to a string of hexadecimal characters.
 *
 * @param hash The hash value to convert.
 * @param hash_len The length of the hash value.
 * @param hex_str The buffer to store the resulting hexadecimal string. It should be at least 2*hash_len + 1 bytes long.
 */
void hash_to_hex(const unsigned char* hash, size_t hash_len, char* hex_str)
{
    for (size_t i = 0; i < hash_len; i++)
    {
        sprintf_s(hex_str + (i * 2), 3, "%02x", hash[i]);
    }
}