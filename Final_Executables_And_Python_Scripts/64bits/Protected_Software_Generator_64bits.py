import angr
import os
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import hmac
import sys
import pefile
import lief

dir = ""
iv = b'\xC2\x40\xEC\xD0\x63\x63\x62\xDF\xBF\xD3\xB8\xF2\x7C\x3B\x80\x02'
hash_function = hashlib.sha256  # RFC5869 also includes SHA-1 test vectors


"""
@brief Retrieves the ImageBase value from a PE file.

@param file_name: Path to the PE file.
@return: ImageBase value as a hexadecimal string, or None if an error occurs.
"""
def get_image_base(file_name):
    try:
        pe = pefile.PE(file_name, fast_load=True)  # Load the PE file in fast_load mode
        image_base = pe.OPTIONAL_HEADER.ImageBase  # Extract ImageBase from PE optional header
        pe.close()  # Close the PE file
        return hex(image_base)  # Return ImageBase as a hexadecimal string
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file '{file_name}': {e}")
        return None
    
"""
@brief Retrieves the start and end addresses of the .text section in an executable file.

@param exe_file_path: Path to the executable file.
@return: A tuple containing the start and end addresses of the .text section.
"""
def get_text_section_addresses(exe_file_path):
    # Load the executable file
    binary = lief.parse(exe_file_path)


    text_section_start = None
    text_section_end = None

    # Iterate through the sections to find the .text section
    for section in binary.sections:
        if section.name == ".text":
            text_section_start = section.offset
            text_section_end = section.offset + section.size
            break
    return text_section_start, text_section_end

"""
@brief Retrieves the virtual address of the .text section in a PE file.

@param file_name: Path to the PE file.
@return: Virtual address of the .text section as a hexadecimal string, or None if not found or an error occurs.
"""
def get_text_section_virtual_address(file_name):
    try:
        pe = pefile.PE(file_name, fast_load=True)  # Load the PE file in fast_load mode
        text_section_va = None

        # Iterate through sections to find the .text section
        for section in pe.sections:
            if section.Name.decode().strip('\x00').lower() == ".text":
                text_section_va = section.VirtualAddress
                break

        pe.close()  # Close the PE file
        return hex(text_section_va) if text_section_va is not None else None
    except pefile.PEFormatError as e:
        print(f"Error parsing PE file '{file_name}': {e}")
        return None

"""
@brief Prints a byte object in hexadecimal format.
@param byte_obj The byte object to be printed in hexadecimal format.
"""
def print_hex_format(byte_obj):
    hex_string = byte_obj.hex()
    formatted_hex = ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
    print(formatted_hex)

"""
@brief Computes the HMAC digest of the given key and data.
@param key The key used for HMAC computation.
@param data The data to be authenticated.
@return The computed HMAC digest.
"""
def hmac_digest(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hash_function).digest()

"""
@brief Performs the HKDF extract step.
@param salt The salt value (a non-secret random value).
@param ikm The input keying material.
@return The extracted pseudorandom key.
"""
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function().digest_size)
    return hmac_digest(salt, ikm)

"""
@brief Performs the HKDF expand step.
@param prk The pseudorandom key.
@param info Optional context and application specific information.
@param length The length of the output keying material in bytes.
@return The output keying material.
"""
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
@brief Performs the complete HKDF key derivation.
@param salt The salt value (a non-secret random value).
@param ikm The input keying material.
@param info Optional context and application specific information.
@param length The length of the output keying material in bytes.
@return The derived key.
"""
def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)

"""
@brief Retrieves relocation addresses from a binary file.
@param binary_path The path to the binary file.
@return A sorted list of relocation addresses.
"""
def get_relocation_addresses(binary_path):
    project = angr.Project(binary_path, auto_load_libs=False)
    main_object = project.loader.main_object
    image_base = main_object.min_addr
    relocation_addresses = set()
    for reloc in main_object.relocs:
        if reloc.symbol is None:
            relocation_addresses.add(reloc.rebased_addr - image_base)
    return sorted(list(relocation_addresses))

"""
@brief Filters basic block ranges based on relocation addresses.
@param ranges A list of address ranges (start, end) representing basic blocks.
@param relocation_addresses A list of relocation addresses.
@return A filtered list of address ranges.
"""
def filter_blocks_by_relocations(ranges, relocation_addresses):
    filtered_ranges = []
    for start, end in ranges:
        block_size = end - start
        expected_relocs = block_size // 8  # Changed from 4 to 8 for 64-bit
        relocs_in_block = sum(1 for addr in relocation_addresses if start <= addr < end)
        if relocs_in_block < expected_relocs:
            filtered_ranges.append((start, end))
    return filtered_ranges

"""
@brief Retrieves basic block address ranges from a binary file.
@param binary_path The path to the binary file.
@param limit_factor The minimum size for a block to be included.
@return A list of address ranges (start, end) for basic blocks.
"""
def get_basic_block_ranges(binary_path, limit_factor):
    project = angr.Project(binary_path, auto_load_libs=False)
    image_base = project.loader.main_object.min_addr
    cfg = project.analyses.CFGFast()
    address_ranges = []
    jump_targets = set()

    for node in cfg.nodes():
        for successor in cfg.get_successors(node):
            jump_targets.add(successor.addr)

    for node in cfg.nodes():
        block_start = node.addr
        block_end = node.addr + node.size

        for target in jump_targets:
            if block_start < target < block_end:
                if target - block_start >= limit_factor:
                    address_ranges.append((block_start, target))
                block_start = target

        if block_end - block_start >= limit_factor:
            address_ranges.append((block_start, block_end))

    address_ranges = [(start - image_base, end - image_base) for start, end in address_ranges]
    address_ranges.sort(key=lambda x: x[0])
    return address_ranges

"""
@brief Disassembles and prints basic blocks from a binary file.
@param binary_path The path to the binary file.
@param limit_factor The minimum size for a block to be disassembled and printed.
"""
def disassemble_and_print_blocks(binary_path, limit_factor):
    project = angr.Project(binary_path, auto_load_libs=False)
    image_base = project.loader.main_object.min_addr
    cfg = project.analyses.CFGFast()

    for node in cfg.nodes():
        block_size = node.size
        if block_size >= limit_factor:
            block = project.factory.block(node.addr, block_size)
            print(f"Basic Block at 0x{node.addr - image_base:x}:")

            for insn in block.capstone.insns:
                print(f"  0x{insn.address - image_base:x}: {insn.mnemonic} {insn.op_str} (size: {insn.size} bytes)")
            print()

PC_ID_LENGTH = 32
AES_KEY_LENGTH = 16
IV_SIZE = 16

"""
@brief Encrypts data using AES-CTR mode.
@param data The data to be encrypted.
@param aes_key The AES key for encryption.
@return The encrypted data.
"""
def encrypt_data(data, aes_key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data

"""
@brief Generates a key using HKDF.
@param address The address used in key generation.
@param file_name The name of the file containing key generation data.
@return The generated key.
"""
def generate_key(address, file_name):
    with open(file_name, 'rb') as file:
        pc_id = file.read(PC_ID_LENGTH)
        key_bytes = file.read(AES_KEY_LENGTH)
        address_bytes = address.to_bytes(8, byteorder='little')
        
        print_hex_format(address_bytes)
        print_hex_format(hkdf(address_bytes, key_bytes, pc_id, AES_KEY_LENGTH))
        
        return hkdf(address_bytes, key_bytes, pc_id, AES_KEY_LENGTH)

"""
@brief Calculates the raw offset between virtual and raw addresses for the text section.
@param project An angr Project object representing the binary.
@return The offset between virtual and raw addresses.
"""
def get_raw_offset(project):
    sections = project.loader.main_object.sections
    text_section = next((section for section in sections if section.name == b'.text'), None)
    if text_section is None:
        raise ValueError("Text section not found")
    return text_section.vaddr - text_section.addr

"""
@brief Encrypts specified blocks in a binary file.
@param file_name The name of the input binary file.
@param blocks A list of address ranges to be encrypted.
@return The name of the output encrypted file.
"""
def enc_blocks(file_name, blocks):
    out_file_name = file_name + "_out.exe"
    shutil.copyfile(file_name, out_file_name)
    project = angr.Project(file_name, auto_load_libs=False)
    raw_factor = int(get_text_section_virtual_address(file_name), 16) - get_text_section_addresses(file_name)[0]
    blocks = sorted(blocks)
    with open(out_file_name, "r+b") as out_file, open(file_name, "rb") as read_file:
        current_position = 0
        for (start_block, end_block) in blocks:
            start_raw = start_block - raw_factor
            print(f"raw address {hex(start_raw)}")
            end_raw = end_block - raw_factor
            if start_raw > current_position:
                read_length = start_raw - current_position
                out_file.write(read_file.read(read_length))
                current_position = start_raw
            read_file.seek(start_raw, 0)
            block_to_encrypt = read_file.read(end_raw - start_raw)
            cur_key = generate_key(start_block, "License.dat")
            encrypted_block = encrypt_data(block_to_encrypt, cur_key)
            out_file.seek(start_raw, 0)
            out_file.write(encrypted_block)
            current_position = end_raw
        remaining_size = os.path.getsize(file_name) - current_position
        if remaining_size > 0:
            out_file.write(read_file.read(remaining_size))
    return out_file_name

"""
@brief Writes block information to a binary file.
@param blocks A list of address ranges (start, end) representing blocks.
"""
def write_blocks_file(blocks):
    block_file_name = dir + "blocks_list.bin"
    with open(block_file_name, 'wb') as block_file:
        for start_address, end_address in blocks:
            start_bytes = start_address.to_bytes(8, 'little', signed=False)
            end_bytes = end_address.to_bytes(8, 'little', signed=False)
            block_file.write(start_bytes)
            block_file.write(end_bytes)

"""
@brief Finds dynamic jumps and calls in a 64-bit executable.
@param exe_path The path to the executable file.
@return A list of addresses of instructions performing dynamic jumps or calls.
"""
def find_dynamic_jumps_calls_64bit(exe_path):
    project = angr.Project(exe_path, auto_load_libs=False)
    entry = project.factory.entry_state()
    cfg = project.analyses.CFGFast()
    image_base = project.loader.main_object.min_addr
    executable_sections = [sec for sec in project.loader.main_object.sections if sec.is_executable]

    if not executable_sections:
        raise ValueError("No executable sections found in the binary")

    text_start = min(sec.min_addr for sec in executable_sections)
    text_end = max(sec.max_addr for sec in executable_sections)

    dynamic_instructions = []

    for addr, function in cfg.functions.items():
        for block in function.blocks:
            for instruction in block.capstone.insns:
                if instruction.insn.mnemonic.startswith('j') or instruction.insn.mnemonic == 'call':
                    op_str = instruction.insn.op_str
                    if any(reg in op_str for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']):
                        dynamic_instructions.append(instruction.address - image_base)
                    elif op_str.startswith('qword ptr'):
                        try:
                            target_addr = int(op_str.split('[')[-1].split(']')[0], 16)
                            if text_start <= target_addr <= text_end:
                                dynamic_instructions.append(instruction.address - image_base)
                        except ValueError:
                            dynamic_instructions.append(instruction.address - image_base)
    return dynamic_instructions

"""
@brief Writes a list of call addresses to a binary file.
@param addresses A list of call addresses to be written.
"""
def write_call_address_file(addresses):
    block_file_name = dir+"call_address_list.bin"
    with open(block_file_name, 'wb') as block_file:
        for address in addresses:
            tmp = address.to_bytes(8, 'little', signed=False)
            block_file.write(tmp)

"""
@brief Retrieves address ranges for .data and .rdata sections.
@param binary_path The path to the binary file.
@return A list of address ranges for .data and .rdata sections.
"""
def get_data_and_rdata_ranges(binary_path):
    project = angr.Project(binary_path, auto_load_libs=False)
    sections = project.loader.main_object.sections
    image_base = project.loader.main_object.min_addr
    ranges = []
    for section in sections:
        if section.name.startswith('.data') or section.name.startswith('.rdata'):
            section_start = section.vaddr
            section_end = section.vaddr + section.memsize
            ranges.append((section_start-image_base, section_end-image_base))
            print(hex(section_start-image_base))
    return ranges

"""
@brief Copies a list of files to an output folder.
@param file_paths A list of file paths to be copied.
"""
def copy_files_to_out(file_paths):
    output_folder = 'out'
    os.makedirs(output_folder, exist_ok=True)
    for file_path in file_paths:
        file_path = file_path.strip()
        if file_path:
            if os.path.isfile(file_path):
                file_name = os.path.basename(file_path)
                dest_path = os.path.join(output_folder, file_name)
                shutil.copy2(file_path, dest_path)
                print(f"Copied {file_path} to {dest_path}")
            else:
                print(f"File not found: {file_path}")

"""
@brief Main function to process the binary file.
@param argc The number of command-line arguments.
@param argv The list of command-line arguments.
"""
def main(argc, argv):
    if argc < 2 or argc > 3:
        print("Usage: python your_script.py <binary_path> [<limit_factor>]")
        return
    binary_path = argv[1]
    limit_factor = int(argv[2]) if argc == 3 else 10
    # Get the address ranges of basic blocks
    reallocation_table = get_relocation_addresses(binary_path)
    for addr in reallocation_table:
        print(addr)
    ranges = get_basic_block_ranges(binary_path, limit_factor)
    ranges = filter_blocks_by_relocations(ranges, reallocation_table)
    ranges = sorted(ranges)
    enc_blocks(binary_path, ranges)
    write_blocks_file(ranges)
    dynamic_jumps = find_dynamic_jumps_calls_64bit(binary_path)
    write_call_address_file(dynamic_jumps)
    file_names = [binary_path + "_out.exe", "public.pem", "License.dat", "Activation_Program.exe", "blocks_list.bin", "call_address_list.bin"]
    copy_files_to_out(file_names)

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)