#pragma once

#include <Windows.h>
#include "Mode.h"
#include <ctime>

/**
 * @brief The License structure represents a software license.
 *
 * This structure contains the PC ID, an AES key, the generation time,
 * and functions for handling RSA key generation, reading keys from files,
 * signing messages, and verifying signatures.
 *
 * The License class makes use of the OpenSSL library for cryptographic
 * operations, including AES encryption, RSA key generation, and digital
 * signatures.
 */
struct License
{
    unsigned char  pc_id[RSA_KEY_LENGTH];        ///< The PC ID associated with the license.
    unsigned char key[SIZE_64];        ///< The AES key used for encryption.
    time_t generation_time;          ///< The time when the license was generated.
    const char FILE_NAME[sizeof(LICENSE_FILENAME) + 1] = LICENSE_FILENAME;  ///< The file name for storing the license data.
    License() {}
    License(const char* fileName);
    /**
     * @brief Handles OpenSSL errors.
     *
     * This function prints OpenSSL error messages to the standard error output
     * and aborts the program.
     */
    static void handleErrors(void);

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
    License(unsigned char pc_id[]);
    /**
     * @brief Generates a license and writes it to a file.
     *
     * This function generates a license, signs it, serializes it along with the signature,
     * and writes it to a file.
     *
     * @return true if the license was successfully generated, signed, and written to the file.
     *         false if an error occurred during file operations or signing process.
     */
    bool gen_license();

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
    static void generateRSAKeyPair();

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
    static bool readPublicKey(char* buffer, size_t buffer_len);

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
    static bool readPrivateKey(char* buffer, size_t buffer_len);

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
    bool sign_license(unsigned char* signature);

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
    bool verifySignature(unsigned char* signature);

    static bool verifyLicense();

    /**
     * @brief Generates a PC ID by hashing various hardware identifiers.
     *
     * This function collects hardware identifiers such as disk UUID, MAC address,
     * volume serial number, processor ID, BIOS UUID, and motherboard ID, concatenates
     * them, and computes a SHA-256 hash to generate a unique PC ID.
     *
     * @param pc_id The buffer to store the generated PC ID.
     */
    static void generatePCID(unsigned char pc_id[SIGNATURE_LENGTH]);
};
