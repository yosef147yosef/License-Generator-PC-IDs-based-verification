#include "License.h"
#include "Helper.h"
#include "sizes.h"
#include <Windows.h>
#include <stdio.h>

/**
 * @brief Prints a byte array as hexadecimal values.
 *
 * This function takes a byte array and its size as input, then prints each byte
 * as a two-digit hexadecimal value to the standard output. The output is not
 * separated by spaces or newlines.
 *
 * @param array Pointer to the byte array to be printed.
 * @param size The number of bytes in the array.
 */
void print_byte_array_as_hex(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X", array[i]);
    }
}


/**
 * @brief Converts a hexadecimal string to a byte array.
 *
 * This function takes a string of hexadecimal characters and converts it to
 * a byte array. It checks for even length of the input string and uses sscanf_s
 * for safe conversion of each pair of hex characters to a byte.
 *
 * @param hex_string The input string of hexadecimal characters.
 * @param output Pointer to the byte array where the result will be stored.
 * @return The number of bytes converted, or 0 if an error occurred.
 */
SIZE_T hex_string_to_bytes(const char* hex_string, BYTE* output) {
    SIZE_T len = strlen(hex_string);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string length must be even.\n");
        return 0;  // Error: Odd-length hex string
    }

    SIZE_T byte_count = len / 2;
    for (SIZE_T i = 0; i < byte_count; i++) {
        sscanf_s(hex_string + 2 * i, "%2hhX", &output[i], sizeof(BYTE));
    }

    return byte_count;
}


/**
 * @brief Main function demonstrating the generation and printing of a PC ID.
 *
 * This function generates a PC ID using the License::generatePCID function,
 * then prints it as a hexadecimal string using the print_byte_array_as_hex function.
 *
 * @return 0 on successful execution.
 */
int main() {

    unsigned char pc_id[PC_ID_LENGTH];
    License::generatePCID(pc_id);
    print_byte_array_as_hex(pc_id, PC_ID_LENGTH);
    return 0;
}
