#pragma once
#include <Windows.h>
#include "License.h"
#include "Mode.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>

int hkdf(const unsigned char* salt, size_t salt_len,
    const unsigned char* ikm, size_t ikm_len,
    const unsigned char* info, size_t info_len,
    unsigned char* okm, size_t okm_len)
{
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* kctx = NULL;
    OSSL_PARAM params[5], * p = params;
    int ret = 0;

    /* Create a context for the HKDF operation */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return 0;  // Error: Failed to fetch HKDF algorithm
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        EVP_KDF_free(kdf);
        return 0;  // Error: Failed to create HKDF context
    }

    /* Set the parameters */
    *p++ = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void*)ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", (void*)info, info_len);
    *p = OSSL_PARAM_construct_end();

    /* Derive the key */
    if (EVP_KDF_derive(kctx, okm, okm_len, params) > 0) {
        ret = 1;  // Success
    }

    /* Clean up */
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    return ret;
}
void ADDR_TYPEToByteArray(ADDR_TYPE value, BYTE byteArray[]) {
    for (int i = 0; i < sizeof(ADDR_TYPE); ++i) {
        byteArray[i] = (BYTE)((value >> (8 * (3 - i))) & 0xFF);
    }
}
void print_byte_array_as_hex1(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", array[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}
void gen_key(ADDR_TYPE start_address, License& license, BYTE key[])
{
    SIZE_T size;
    BYTE salt[sizeof(ADDR_TYPE)];
    ADDR_TYPEToByteArray(start_address, salt);
    print_byte_array_as_hex1(salt, 4);
    BYTE info[] = { 'b','b','b' };
    BYTE k[] = { 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a' };
    hkdf(salt, sizeof(ADDR_TYPE), k, AES_KEY_LENGTH, info, 3, key, AES_KEY_LENGTH);
    print_byte_array_as_hex1(key, 16);
}