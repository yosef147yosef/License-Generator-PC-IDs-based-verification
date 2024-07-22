#include "License.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <cstring>
#include "Helper.h"

/**
 * @brief Generates a new RSA key pair and saves them to files if they do not already exist.
 *
 * This function checks if the public and private key files exist. If both files already exist,
 * the function returns without generating new keys. If either file is missing, it proceeds to
 * generate a new RSA key pair of the specified length and saves them to the respective files.
 *
 * @note This function uses the OpenSSL library for RSA key generation and file I/O operations.
 *
 * @return Void. If successful, new RSA key pair files are created on the filesystem.
 *         If an error occurs during key generation or file operations, the function may abort.
 */
void License::generateRSAKeyPair() {
    FILE* public_key_file = NULL;
    FILE* private_key_file = NULL;
    int ret;

    ret = fopen_s(&public_key_file, PUBLIC_KEY_FILENAME, "r");
    if (ret == 0 && public_key_file != NULL) {
        fclose(public_key_file);
    }

    ret = fopen_s(&private_key_file, PRIVATE_KEY_FILENAME, "r");
    if (ret == 0 && private_key_file != NULL) {
        fclose(private_key_file);
    }

    if (public_key_file != NULL && private_key_file != NULL) {
        return;
    }

    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret <= 0) handleErrors();

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_LENGTH);
    if (ret <= 0) handleErrors();

    ret = EVP_PKEY_keygen(ctx, &pkey);
    if (ret <= 0) handleErrors();

    BIO* bio_private = BIO_new_file(PRIVATE_KEY_FILENAME, "w+");
    if (!bio_private) handleErrors();

    ret = PEM_write_bio_PrivateKey(bio_private, pkey, NULL, NULL, 0, NULL, NULL);
    if (ret <= 0) handleErrors();

    BIO* bio_public = BIO_new_file(PUBLIC_KEY_FILENAME, "w+");
    if (!bio_public) handleErrors();

    ret = PEM_write_bio_PUBKEY(bio_public, pkey);
    if (ret <= 0) handleErrors();

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(bio_private);
    BIO_free_all(bio_public);
}

/**
 * @brief Reads the public key from the file and stores it in a buffer.
 *
 * This function reads the public key from the specified file and writes it
 * to the provided buffer. It uses OpenSSL's BIO and PEM functions to handle
 * the file operations and key formatting.
 *
 * @param buffer The buffer to store the public key.
 * @param buffer_len The length of the buffer.
 * @return true if the public key was successfully read and stored in the buffer.
 *         false if an error occurred.
 */
bool License::readPublicKey(char* buffer, size_t buffer_len) {
    BIO* bio_public = BIO_new_file(PUBLIC_KEY_FILENAME, "r");
    if (!bio_public) {
        printf("ERROR opening public key file\n");
        return false;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio_public, NULL, NULL, NULL);
    if (!pkey) {
        printf("ERROR reading public key\n");
        BIO_free(bio_public);
        return false;
    }

    BIO* bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        handleErrors();
    }

    if (!PEM_write_bio_PUBKEY(bio_mem, pkey)) {
        printf("ERROR writing public key to BIO\n");
        BIO_free(bio_mem);
        BIO_free(bio_public);
        EVP_PKEY_free(pkey);
        return false;
    }

    int keylen = BIO_pending(bio_mem);
    if (keylen > buffer_len) {
        printf("Buffer is too small for the public key\n");
        BIO_free(bio_mem);
        BIO_free(bio_public);
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO_read(bio_mem, buffer, keylen);
    buffer[keylen] = '\0';

    BIO_free(bio_mem);
    BIO_free(bio_public);
    EVP_PKEY_free(pkey);

    return true;
}

/**
 * @brief Reads the private key from the file and stores it in a buffer.
 *
 * This function reads the private key from the specified file and writes it
 * to the provided buffer. It uses OpenSSL's BIO and PEM functions to handle
 * the file operations and key formatting.
 *
 * @param buffer The buffer to store the private key.
 * @param buffer_len The length of the buffer.
 * @return true if the private key was successfully read and stored in the buffer.
 *         false if an error occurred.
 */
bool License::readPrivateKey(char* buffer, size_t buffer_len) {
    BIO* bio_private = BIO_new_file(PRIVATE_KEY_FILENAME, "r");
    if (!bio_private) {
        printf("ERROR opening private key file\n");
        return false;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_private, NULL, NULL, NULL);
    if (!pkey) {
        printf("ERROR reading private key\n");
        BIO_free(bio_private);
        return false;
    }

    BIO* bio_mem = BIO_new(BIO_s_mem());
    if (!bio_mem) {
        handleErrors();
    }

    if (!PEM_write_bio_PrivateKey(bio_mem, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("ERROR writing private key to BIO\n");
        BIO_free(bio_mem);
        BIO_free(bio_private);
        EVP_PKEY_free(pkey);
        return false;
    }

    int keylen = BIO_pending(bio_mem);
    if (keylen > buffer_len) {
        printf("Buffer is too small for the private key\n");
        BIO_free(bio_mem);
        BIO_free(bio_private);
        EVP_PKEY_free(pkey);
        return false;
    }

    BIO_read(bio_mem, buffer, keylen);
    buffer[keylen] = '\0';

    BIO_free(bio_mem);
    BIO_free(bio_private);
    EVP_PKEY_free(pkey);

    return true;
}


/**
 * @brief Signs the License object using the private key and stores the signature in the provided buffer.
 *
 * This function reads the private key from the file, then signs the entire License object
 * using SHA-256 and RSA. The generated signature is stored in the provided buffer.
 *
 * @param signature The buffer to store the generated signature.
 * @return true if the message was successfully signed.
 *         false if an error occurred.
 */
bool License::sign_license(unsigned char* signature) {
    BIO* bio_private = BIO_new_file(PRIVATE_KEY_FILENAME, "r");
    if (!bio_private) {
        printf("ERROR opening private key file\n");
        return false;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_private, NULL, NULL, NULL);
    if (!pkey) {
        printf("ERROR reading private key\n");
        BIO_free(bio_private);
        return false;
    }
    size_t signature_length = SIGNATURE_LENGTH;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) handleErrors();
    if (EVP_DigestSignUpdate(mdctx, this, sizeof(*this)) <= 0) handleErrors();
    if (EVP_DigestSignFinal(mdctx, NULL, &signature_length) <= 0) handleErrors();
    if (EVP_DigestSignFinal(mdctx, signature, &signature_length) <= 0) handleErrors();

    if (signature_length > SIGNATURE_LENGTH) {
        printf("Warning: Signature size (%zu) is larger than expected (%d)\n", signature_length, SIGNATURE_LENGTH);
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio_private);

    return true;
}

/**
 * @brief Verifies the signature of the License object using the public key.
 *
 * This function reads the public key from the file, then verifies the signature
 * of the entire License object using SHA-256 and RSA.
 *
 * @param signature The signature to verify.
 * @return true if the signature is valid.
 *         false if the signature is invalid or an error occurred.
 */
bool License::verifySignature(unsigned char* signature) {
    BIO* bio_public = BIO_new_file(PUBLIC_KEY_FILENAME, "r");
    if (!bio_public) {
        printf("ERROR opening public key file\n");
        return false;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio_public, NULL, NULL, NULL);
    if (!pkey) {
        printf("ERROR reading public key\n");
        BIO_free(bio_public);
        return false;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) handleErrors();
    if (EVP_DigestVerifyUpdate(mdctx, this, sizeof(*this)) <= 0) handleErrors();
    int verify_result = EVP_DigestVerifyFinal(mdctx, signature, SIGNATURE_LENGTH);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio_public);
    return verify_result == 1 ? 1 : 0;
}

/**
 * @brief Handles OpenSSL errors.
 *
 * This function prints OpenSSL error messages to the standard error output
 * and aborts the program.
 */
void License::handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Constructs a new License object with the given PC ID.
 *
 * This constructor initializes the License object with the provided PC ID,
 * generates a generation time, and seeds the random number generator with
 * a combination of the PC ID and the generation time. It then generates a
 * random AES key and RSA key pair.
 *
 * @param PC_ID The PC ID to initialize the License object.
 */
License::License(unsigned char* PC_ID)
{
    memcpy_s(this->pc_id, PC_ID_LENGTH, PC_ID, PC_ID_LENGTH);
    generation_time = time(NULL);
    BYTE seed[AES_KEY_LENGTH + sizeof(generation_time)];
    memcpy_s(seed, AES_KEY_LENGTH + sizeof(generation_time), PC_ID, AES_KEY_LENGTH);
    memcpy_s(seed + AES_KEY_LENGTH, sizeof(generation_time), &generation_time, sizeof(generation_time));
    RAND_seed(seed, AES_KEY_LENGTH + sizeof(generation_time));
    if (!RAND_bytes(key, AES_KEY_LENGTH)) {
        handleErrors();
    }
    generateRSAKeyPair();
}

/**
 * @brief Generates a license and writes it to a file.
 *
 * This function generates a license, signs it, serializes it along with the signature,
 * and writes it to a file.
 *
 * @return true if the license was successfully generated, signed, and written to the file.
 *         false if an error occurred during file operations or signing process.
 */
bool License::gen_license() {
    FILE* file;
    errno_t err = fopen_s(&file, LICENSE_FILENAME, "wb");
    if (err != 0)
    {
        return false;
    }
    // Write the License object to the file
    unsigned char l[sizeof(*this) + SIGNATURE_LENGTH];
    memcpy_s(l, sizeof(*this), this, sizeof(*this));
    sign_license(l + sizeof(*this));
    if (fwrite(l, sizeof(*this) + SIGNATURE_LENGTH, 1, file) != 1)
    {
        fclose(file);
        return false;
    }
    fclose(file);
    return true;
}

bool License::verifyLicense() {
    FILE* file;
    fopen_s(&file, LICENSE_FILENAME, "rb");
    if (!file) {
        return false;
    }

    // Read the License object from the file
    License license;
    size_t license_size = fread(&license, sizeof(License), 1, file);
    if (license_size != 1) {
        return false;
    }

    // Read the signature from the end of the file
    fseek(file, -SIZE_64, SEEK_END);
    unsigned char signature[SIZE_64];
    size_t signature_size = fread(signature, sizeof(unsigned char), SIZE_64, file);
    fclose(file);
    // Verify the signature
    return license.verifySignature(signature);
}

/**
 * @brief Generates a unique PC ID based on hardware identifiers.
 *
 * This function collects hardware identifiers such as disk UUID, MAC address,
 * volume serial number, processor ID, BIOS UUID, and motherboard ID. It concatenates
 * these identifiers into a single string and computes the SHA-256 hash, storing
 * the result in the provided buffer.
 *
 * @param pc_id The buffer to store the generated PC ID.
 *
 * @note The SHA256_DIGEST_LENGTH constant, defined by OpenSSL, specifies that the SHA-256 hash
 * has a length of 256 bits (32 bytes).
 */
void License::generatePCID(unsigned char* pc_id) {
    char diskUUID[SIZE_64] = { 0 };
    char biosUUID[SIZE_64] = { 0 };
    char motherboardID[SIZE_64] = { 0 };
    char MAC_address[SIZE_64] = { 0 };
    DWORD volumeSerialNumber;
    char cpuId[SIGNATURE_LENGTH] = { 0 };
    char concatenatedIDs[CONCATENATE_SIZE] = { 0 };
    unsigned char hashedIDs[SHA256_DIGEST_LENGTH] = { 0 };
    char hexStr[SHA256_DIGEST_LENGTH * 2 + 1] = { 0 };

    // Get hardware IDs
    GetDiskUUID(diskUUID);
    //printf("\nGetDiskUUID: %s\n", diskUUID);

    GetMACAddress(MAC_address);
    //printf("\nGetMACAddress: %s\n", MAC_address);

    getSerialNumber(&volumeSerialNumber);
    //printf("\ngetSerialNumber: %lu\n", volumeSerialNumber);

    getProcessorId(cpuId);
    //printf("\ngetProcessorId: %s\n", cpuId);

    GetMotherboardID(motherboardID);
    //printf("\nGetMotherboardID: %s\n", motherboardID);

    // Concatenate all IDs into a single string
    snprintf(concatenatedIDs, sizeof(concatenatedIDs), "%s%s%lu%s%s%s",
        diskUUID, MAC_address, volumeSerialNumber, cpuId, biosUUID, motherboardID);

    //printf("\nconcatenatedIDs: %s\n", concatenatedIDs);


    // Hash the concatenated string
    sha256(hashedIDs, concatenatedIDs);

    // Convert the hash to a hexadecimal string
    hash_to_hex(hashedIDs, SHA256_DIGEST_LENGTH, hexStr);
    //printf("Hash in hex : %s\n", hexStr);

    // Copy the hashed IDs to the pc_id buffer
    memcpy_s(pc_id, PC_ID_LENGTH, hashedIDs, PC_ID_LENGTH);
}




