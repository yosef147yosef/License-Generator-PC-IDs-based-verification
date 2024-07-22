#pragma once
#include <Windows.h>
#include "License.h"
#include "Mode.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>


/**
 * @brief Performs HKDF (HMAC-based Key Derivation Function) operation.
 *
 * This function uses OpenSSL's EVP API to perform HKDF with SHA256.
 * It derives a key using the provided salt, input key material (IKM), and info.
 *
 * @param salt Pointer to the salt.
 * @param salt_len Length of the salt.
 * @param ikm Pointer to the input key material.
 * @param ikm_len Length of the input key material.
 * @param info Pointer to the info.
 * @param info_len Length of the info.
 * @param okm Pointer to the output key material.
 * @param okm_len Length of the output key material.
 * @return 1 on success, 0 on failure.
 */
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

/**
 * @brief Converts an ADDR_TYPE value to a byte array.
 *
 * This function takes an ADDR_TYPE value and converts it to a byte array,
 * with the most significant byte first (big-endian order).
 *
 * @param value The ADDR_TYPE value to convert.
 * @param byteArray The output byte array.
 */
void ADDR_TYPEToByteArray(ADDR_TYPE value, BYTE byteArray[]) {
    for (int i = 0; i < sizeof(ADDR_TYPE); ++i) {
        byteArray[i] = (BYTE)((value >> (8 * (3 - i))) & 0xFF);
    }
}


/**
 * @brief Prints a byte array as hexadecimal values.
 *
 * This function takes a byte array and its size, then prints each byte as a two-digit hexadecimal value.
 * It adds a newline after every 16 bytes for better readability.
 *
 * @param array The byte array to print.
 * @param size The size of the byte array.
 */
void print_byte_array_as_hex1(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X ", array[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * @brief Generates a key using HKDF.
 *
 * This function generates a key using HKDF with the provided start address, license information, and PC ID.
 * It uses the start address as salt, the license key as input key material, and the PC ID as info.
 *
 * @param start_address The start address to use as salt.
 * @param license The license object containing the key and PC ID.
 * @param key The output buffer for the generated key.
 */
void gen_key(ADDR_TYPE start_address, License& license, BYTE key[])
{
    SIZE_T size;
    BYTE salt[sizeof(ADDR_TYPE)];
    ADDR_TYPEToByteArray(start_address, salt);
    static bool pc_id_genreated = false;
    static BYTE info[PC_ID_LENGTH];
    if (!pc_id_genreated)
    {
        License::generatePCID(info);
        pc_id_genreated = true;
    }
    hkdf(salt, sizeof(ADDR_TYPE), license.key, AES_KEY_LENGTH, info ,PC_ID_LENGTH, key, AES_KEY_LENGTH);
}