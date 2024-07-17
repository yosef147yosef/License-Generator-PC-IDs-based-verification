#pragma once
#include <Windows.h>
#include "License.h"
#include "Mode.h"
void gen_key(ADDR_TYPE start_address, License& license, BYTE key[])
{
    SIZE_T size;
    memcpy_s(key, AES_KEY_LENGTH, license.key, AES_KEY_LENGTH);
}