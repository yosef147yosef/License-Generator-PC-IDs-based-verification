import pefile
import lief

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
