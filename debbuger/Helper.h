#pragma once
#include <windows.h>
#include "sizes.h"

/**
 * @brief Gets the disk UUID.
 *
 * @param diskUUID The buffer to store the disk UUID.
 */
void GetDiskUUID(char* diskUUID);

/**
 * @brief Gets the MAC address of the system.
 *
 * @param MAC_address The buffer to store the MAC address.
 */
void GetMACAddress(char* MAC_address);

/**
 * @brief Gets the volume serial number.
 *
 * @param volumeSerialNumber Pointer to store the volume serial number.
 */
void getSerialNumber(DWORD* volumeSerialNumber);

/**
 * @brief Gets the processor ID.
 *
 * @param cpuId The buffer to store the processor ID.
 */
void getProcessorId(char* cpuId);

/**
 * @brief Gets the motherboard ID.
 *
 * @param motherboardID The buffer to store the motherboard ID.
 */
void GetMotherboardID(char* motherboardID);

/**
 * @brief Computes the SHA-256 hash of a string.
 *
 * @param hashedIDs The buffer to store the computed hash.
 * @param str The input string to hash.
 */
void sha256(unsigned char* hashedIDs, const char* str);