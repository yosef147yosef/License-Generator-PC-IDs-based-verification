#pragma once
#include "Mode.h"
#include <Windows.h>
#include <stdio.h>


/**
 * @brief Reads call addresses from a binary file.
 *
 * This function opens a binary file and reads ADDR_TYPE values into a vector.
 * It continues reading until either the maximum number of addresses (MAX_ADDRESSES)
 * is reached or the end of the file is encountered.
 *
 * @param filename The name of the binary file to read from.
 * @param addresses A vector to store the read addresses.
 */
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
