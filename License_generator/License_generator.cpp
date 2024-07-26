#include "License.h"
#include "Helper.h"
#include "sizes.h"
#include <Windows.h>
#include <stdio.h>
void print_byte_array_as_hex(BYTE* array, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        printf("%02X", array[i]);
    }
}
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
