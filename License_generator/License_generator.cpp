#include "License.h"
#include "Helper.h"
#include "sizes.h"
#include <Windows.h>
#include <stdio.h>

/**
 * @brief Prints a byte array as hexadecimal values.
 *
 * This function takes a byte array and its size, then prints each byte as a two-digit hexadecimal value.
 *
 * @param array Pointer to the byte array to be printed.
 * @param size Size of the byte array.
 */
void print_byte_array_as_hex(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X", array[i]);
    }
}

/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * This function takes a hexadecimal string and converts it to a byte array.
 * It assumes that each byte is represented by two hexadecimal characters.
 *
 * @param hex_string The input hexadecimal string.
 * @param len Length of the hexadecimal string.
 * @param output Pointer to the output byte array.
 * @return The number of bytes written to the output array, or 0 if an error occurred.
 */
SIZE_T hex_string_to_bytes(const char* hex_string, SIZE_T len ,  BYTE* output) {
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string length must be even.\n");
        return 0;  // Error: Odd-length hex string
    }
    SIZE_T byte_count = len/2;
    for (SIZE_T i = 0; i < byte_count; i++) {
        sscanf_s(hex_string + 2 * i, "%2hhX", &output[i], sizeof(BYTE));
        
    }
    return byte_count;
}

/**
 * @brief Main function for the license generation program.
 *
 * This function handles the command-line arguments, creates a License object,
 * signs the license, and generates the license file.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return 0 if successful, 1 if there's an error in arguments.
 */
int main(int argc, char* argv[]) {

    if (argc < 2)
    {
        printf("Usage: %s <pc_id>\n", argv[0]);
        return 1;
    }
    char pc_id[PC_ID_LENGTH * 2 + 1];
    unsigned char signature[SIGNATURE_LENGTH];
    // Copy PC ID from command-line argument with safe function
    memcpy(pc_id, argv[1], PC_ID_LENGTH * 2 );
    BYTE pc_id_final[PC_ID_LENGTH];
    // Copy PC ID from command-line argument with safe function
   hex_string_to_bytes(pc_id, PC_ID_LENGTH*2, pc_id_final);
    //print_byte_array_as_hex(pc_id_final, PC_ID_LENGTH);
    // Create License object with generated PC ID
    License l(pc_id_final);
    l.sign_license(signature);

    // Sign the license
    l.sign_license(signature);

    // Generate the license (assuming this method generates some data or file)
    l.gen_license();

    // Verify the license

    return 0;
}
