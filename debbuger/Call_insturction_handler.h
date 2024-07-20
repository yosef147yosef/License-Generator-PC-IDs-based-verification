#pragma once
#include "Mode.h"
#include <Windows.h>
#include <stdio.h>

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
