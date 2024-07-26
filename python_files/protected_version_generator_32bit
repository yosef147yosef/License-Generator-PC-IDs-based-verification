"""
This script performs various operations on binary files, including encryption,
key generation, and analysis of executable sections.
"""

import angr
import os
import shutil
import get_exe_fields
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import hmac
dir = ""
iv = b'\xC2\x40\xEC\xD0\x63\x63\x62\xDF\xBF\xD3\xB8\xF2\x7C\x3B\x80\x02'
hash_function = hashlib.sha256  # RFC5869 also includes SHA-1 test vectors

"""
@brief Prints a byte object in hexadecimal format with space separation.

@param byte_obj: The byte object to be printed.
"""
def print_hex_format(byte_obj):
    hex_string = byte_obj.hex()
    formatted_hex = ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
    print(formatted_hex)

def hmac_digest(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_function).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function().digest_size)
    return hmac_digest(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac_digest(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]

"""
@brief Implements the HKDF (HMAC-based Key Derivation Function) algorithm.

@param salt: Salt value for HKDF.
@param ikm: Input keying material.
@param info: Context and application specific information.
@param length: Length of the output key material.
@return: The derived key of specified length.
"""
def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)

"""
@brief Retrieves the addresses of absolute relocations in a binary file.

@param binary_path: Path to the binary file.
@return: A sorted list of relocation addresses.
"""
def get_relocation_addresses(binary_path):
    # Load the binary
    project = angr.Project(binary_path, auto_load_libs=False)

    # Get the main binary object
    main_object = project.loader.main_object

    # Get the image base
    image_base = main_object.min_addr

    # Get all relocation entries
    relocation_addresses = set()
    for reloc in main_object.relocs:
        if reloc.symbol is None:  # We're only interested in absolute relocations
            relocation_addresses.add(reloc.rebased_addr - image_base)

    return sorted(list(relocation_addresses))


"""
@brief Filters out blocks that contain exactly the expected number of relocations.

@param ranges: List of address ranges to filter.
@param relocation_addresses: List of relocation addresses.
@return: Filtered list of address ranges.
"""
def filter_blocks_by_relocations(ranges, relocation_addresses):
    filtered_ranges = []
    for start, end in ranges:
        block_size = end - start
        expected_relocs = block_size // 4
        # Count relocations in this block
        relocs_in_block = sum(1 for addr in relocation_addresses if start <= addr < end)
        # Keep the block if it doesn't contain exactly the expected number of relocations
        if relocs_in_block < expected_relocs:
            filtered_ranges.append((start, end))
    return filtered_ranges

"""
@brief Retrieves the address ranges of basic blocks in a binary file.

@param binary_path: Path to the binary file.
@param limit_factor: Minimum size for a block to be considered.
@return: List of tuples representing address ranges of basic blocks.
"""
def get_basic_block_ranges(binary_path, limit_factor):
    # Create an angr project with the given binary file
    project = angr.Project(binary_path, auto_load_libs=False)

    # Get the image base address
    image_base = project.loader.main_object.min_addr

    # Create a CFG (Control Flow Graph) to get all basic blocks
    cfg = project.analyses.CFGFast()

    # List to store the address ranges of basic blocks
    address_ranges = []

    # Set to store all jump targets
    jump_targets = set()

    # First pass: collect all jump targets
    for node in cfg.nodes():
        for successor in cfg.get_successors(node):
            jump_targets.add(successor.addr)

    # Second pass: create blocks considering jump targets
    for node in cfg.nodes():
        block_start = node.addr
        block_end = node.addr + node.size

        # Split the block if there are any jump targets within it
        for target in jump_targets:
            if block_start < target < block_end:
                if target - block_start >= limit_factor:
                    address_ranges.append((block_start, target))
                block_start = target

        # Add the remaining block if it's large enough
        if block_end - block_start >= limit_factor:
            address_ranges.append((block_start, block_end))

    # Adjust address ranges by subtracting the image base
    address_ranges = [(start - image_base, end - image_base) for start, end in address_ranges]

    # Sort the ranges by start address
    address_ranges.sort(key=lambda x: x[0])

    return address_ranges

def disassemble_and_print_blocks(binary_path, limit_factor):
    # Create an angr project with the given binary file
    project = angr.Project(binary_path, auto_load_libs=False)

    # Get the image base address
    image_base = project.loader.main_object.min_addr

    # Create a CFG (Control Flow Graph) to get all basic blocks
    cfg = project.analyses.CFGFast()

    # Iterate over the basic blocks in the CFG
    for node in cfg.nodes():
        block_size = node.size
        if block_size >= limit_factor:
            block = project.factory.block(node.addr, block_size)
            print(f"Basic Block at 0x{node.addr - image_base:x}:")

            for insn in block.capstone.insns:
                print(f"  0x{insn.address - image_base:x}: {insn.mnemonic} {insn.op_str} (size: {insn.size} bytes)")
            print()  # Print a newline for readability between blocks

PC_ID_LENGTH = 32
AES_KEY_LENGTH = 16
IV_SIZE = 16  # AES-CTR requires an IV of 16 bytes


"""
@brief Encrypts data using AES-CTR mode.

@param data: The data to be encrypted.
@param aes_key: The AES key for encryption.
@return: The encrypted data.
"""
def encrypt_data(data, aes_key):
    # Create AES-CTR cipher object
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Encrypt data
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Return the encrypted data
    return encrypted_data


"""
@brief Generates a key using HKDF based on the given address and file content.

@param address: The address to use in key generation.
@param file_name: The name of the file containing necessary data.
@return: The generated key.
"""
def generate_key(address, file_name):
    with open(file_name, 'rb') as file:
        # Seek to the starting position in the file
        # Read AES_KEY_LENGTH bytes from the file
        pc_id = file.read(PC_ID_LENGTH)
        key_bytes = file.read(AES_KEY_LENGTH)
        print_hex_format(key_bytes)
        print_hex_format(hkdf(address.to_bytes(4),key_bytes, pc_id,AES_KEY_LENGTH))
        return hkdf(address.to_bytes(4),key_bytes, pc_id,AES_KEY_LENGTH)

def get_raw_offset(project):
    """
    Get the raw offset between virtual and raw addresses for the text section.

    :param project: angr Project object.
    :return: Offset between virtual and raw addresses.
    """
    # List all sections
    sections = project.loader.main_object.sections
    text_section = None
    for section in sections:
        if section.name == b'.text':  # Adjust if the section name is different
            text_section = section
            break

    if text_section is None:
        raise ValueError("Text section not found")

    # Get virtual and raw addresses
    virtual_start = text_section.vaddr
    raw_start = text_section.addr

    # Calculate the offset
    offset = virtual_start - raw_start
    return offset


"""
@brief Encrypts specified blocks in a file and creates a new output file.

@param file_name: Name of the input file.
@param blocks: List of block ranges to encrypt.
@return: Name of the output file.
"""
def enc_blocks(file_name, blocks):
    # Copy the original file to create the output file
    out_file_name = file_name + "_out.exe"
    shutil.copyfile(file_name, out_file_name)
    project = angr.Project(file_name, auto_load_libs=False)
    # Calculate the offset between virtual and raw addresses
    raw_factor = int(get_exe_fields.get_text_section_virtual_address(file_name), 16) - get_exe_fields.get_text_section_addresses(file_name)[0]
    # Open the copied file to read and write
    blocks = sorted(blocks)
    with open(out_file_name, "r+b") as out_file, open(file_name, "rb") as read_file:
        current_position = 0
        for (start_block, end_block) in blocks:
            start_raw = start_block - raw_factor
            print(f"raw address {hex(start_raw)}")
            end_raw = end_block - raw_factor
            # Copy the part before the current block
            if start_raw > current_position:
                read_length = start_raw - current_position
                out_file.write(read_file.read(read_length))
                current_position = start_raw
            # Encrypt and write the current block
            read_file.seek(start_raw,0)
            block_to_encrypt = read_file.read(end_raw - start_raw)
            cur_key = generate_key(start_block, "License.dat")
            encrypted_block = encrypt_data(block_to_encrypt, cur_key)
            out_file.seek(start_raw,0)
            out_file.write(encrypted_block)
            current_position = end_raw
        # Copy the remaining part of the file after the last block
        remaining_size = os.path.getsize(file_name) - current_position
        if remaining_size > 0:
            out_file.write(read_file.read(remaining_size))
    return out_file_name

def write_blocks_file(blocks):
    block_file_name = dir + "blocks_list.bin"
    with open(block_file_name, 'wb') as block_file:
        for start_address, end_address in blocks:
            start_bytes = start_address.to_bytes(4, byteorder='little', signed=False)
            end_bytes = end_address.to_bytes(4, byteorder='little', signed=False)
            # Write the bytes for start and end addresses
            block_file.write(start_bytes)
            block_file.write(end_bytes)

"""
@brief Finds dynamic jumps and calls in a 32-bit executable.

@param exe_path: Path to the executable file.
@return: List of addresses of dynamic instructions.
"""
def find_dynamic_jumps_calls_32bit(exe_path):
    # Load the binary
    project = angr.Project(exe_path, auto_load_libs=False)

    # Get the entry point
    entry = project.factory.entry_state()

    # Create a CFG (Control Flow Graph)
    cfg = project.analyses.CFGFast()

    # Get the image base
    image_base = project.loader.main_object.min_addr

    # Find executable sections
    executable_sections = [
        sec for sec in project.loader.main_object.sections
        if sec.is_executable
    ]

    if not executable_sections:
        raise ValueError("No executable sections found in the binary")

    # Combine all executable sections
    text_start = min(sec.min_addr for sec in executable_sections)
    text_end = max(sec.max_addr for sec in executable_sections)

    dynamic_instructions = []

    for addr, function in cfg.functions.items():
        for block in function.blocks:
            for instruction in block.capstone.insns:
                # Check if the instruction is a jump or call
                if instruction.insn.mnemonic.startswith('j') or instruction.insn.mnemonic == 'call':
                    op_str = instruction.insn.op_str

                    # Check if the target is a register
                    if any(reg in op_str for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']):
                        dynamic_instructions.append(instruction.address - image_base)

                    # Check if the target is a memory reference (dword ptr) in an executable section
                    elif op_str.startswith('dword ptr'):
                        try:
                            # Try to extract the target address
                            target_addr = int(op_str.split('[')[-1].split(']')[0], 16)
                            if text_start <= target_addr <= text_end:
                                dynamic_instructions.append(instruction.address - image_base)
                        except ValueError:
                            # If we can't parse the address, it's likely a complex expression
                            # We'll consider it as potentially jumping to an executable section
                            dynamic_instructions.append(instruction.address - image_base)

    return dynamic_instructions
def write_call_address_file(addresses):
    block_file_name = dir+"call_address_list.bin"
    with open(block_file_name, 'wb') as block_file:
        for address in addresses:
            tmp = address.to_bytes(4, byteorder='little', signed=False)
            # Write the bytes for start and end addresses
            block_file.write(tmp)


def get_data_and_rdata_ranges(binary_path):
    # Create an angr project with the given binary file
    project = angr.Project(binary_path, auto_load_libs=False)

    # Get all sections
    sections = project.loader.main_object.sections
    image_base = project.loader.main_object.min_addr
    # List to store the address ranges of .data and .rdata sections
    ranges = []
    # Iterate over all sections to find .data and .rdata sections
    for section in sections:
        if section.name.startswith('.data') or section.name.startswith('.rdata'):
            section_start = section.vaddr
            section_end = section.vaddr + section.memsize
            ranges.append((section_start-image_base, section_end-image_base))
            print(hex(section_start-image_base))
    return ranges
def copy_files_to_out(file_paths):
    """
    Copies a list of files to an output folder named 'out'.
    
    :param file_paths: List of file paths to copy.
    """
    output_folder = 'out'
    
    # Ensure the output folder exists
    os.makedirs(output_folder, exist_ok=True)
    
    for file_path in file_paths:
        file_path = file_path.strip()  # Remove any leading/trailing whitespace
        if file_path:
            if os.path.isfile(file_path):
                # Get the base name of the file
                file_name = os.path.basename(file_path)
                # Construct the destination path
                dest_path = os.path.join(output_folder, file_name)
                # Copy the file
                shutil.copy2(file_path, dest_path)
                print(f"Copied {file_path} to {dest_path}")
            else:
                print(f"File not found: {file_path}")

"""
Main execution block of the script.
Performs various operations including block encryption, 
writing block information, and copying files to an output directory.
"""
if __name__ == "__main__":
    binary_path = dir + "SofwareToDemostrate.exe"
    limit_factor = 1  # Example limit factor
    # Get the address ranges of basic blocks
    reallocation_table = get_relocation_addresses(binary_path)
    for addr in reallocation_table:
        print(addr)
    ranges = get_basic_block_ranges(binary_path, limit_factor)
    ranges =  filter_blocks_by_relocations(ranges,reallocation_table)
    #ranges+=get_data_and_rdata_ranges(binary_path)
    ranges = sorted(ranges)
    enc_blocks(binary_path, ranges)
    write_blocks_file(ranges)
    dynmic_jumps = find_dynamic_jumps_calls_32bit(binary_path)
    write_call_address_file(dynmic_jumps)
    file_names = ["SofwareToDemostrate.exe_out.exe","public.pem","License.dat","Actiavtion_Progarm.exe", "blocks_list.bin", "call_address_list.bin"]
    copy_files_to_out(file_names)
