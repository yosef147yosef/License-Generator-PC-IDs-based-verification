#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h> 
#include <map>
#include "Crypto.h"
#include <stdbool.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "Debbuger.h"
#include "Get_Reallocations.h"
#include <set>
#include "Call_insturction_handler.h"
#include <algorithm>
#include "Key_Gen.h"
#define MAX_PATH_LENGTH 128
#define MAX_NAME_LENGTH 64
/**
 * @brief Retrieves the full path of an executable file.
 *
 * This function searches for the specified executable file in the system's PATH
 * and returns its full path. It uses the Windows API function SearchPathA to locate the file.
 *
 * @param exe_name The name of the executable file to search for.
 * @param out_buffer Buffer to store the full path of the executable.
 * @param buffer_size Size of the output buffer.
 * @return true if the executable path was found successfully, false otherwise.
 */
bool get_exe_path(const char* exe_name, char* out_buffer, size_t buffer_size) {
    if (out_buffer == NULL || buffer_size == 0) {
        fprintf(stderr, "Invalid output buffer\n");
        return false;
    }

    DWORD result = SearchPathA(NULL, exe_name, ".exe", buffer_size, out_buffer, NULL);

    if (result == 0) {
        DWORD error = GetLastError();
        fprintf(stderr, "Error finding executable: %lu\n", error);
        return false;
    }

    if (result >= buffer_size) {
        fprintf(stderr, "Path too long for buffer\n");
        return false;
    }

    return true;
}

/**
 * @brief Finds an executable file with "_out.exe" suffix in the current directory.
 *
 * This function searches for the first file in the current directory that ends with "_out.exe".
 * If found, it stores the filename in the provided buffer.
 *
 * @param out_buffer The buffer to store the found filename.
 * @param buffer_size The size of the out_buffer.
 * @return 0 if a file is found, -1 if no file is found or an error occurs.
 */
int find_out_exe_file(char* out_buffer, size_t buffer_size) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(L"*_out.exe", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("No files found.\n");
        return -1;
    }
    else {
        do {
            if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                // Convert wide string to narrow string
                size_t num_converted;
                wcstombs_s(&num_converted, out_buffer, buffer_size, findFileData.cFileName, _TRUNCATE);
                FindClose(hFind);
                return 0;
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);

        FindClose(hFind);
        return -1;  // No matching file found
    }
}

/**
 * @brief Main function to handle the creation, suspension, and debugging of a process.
 *
 * This function creates a new process in a suspended state, sets breakpoints,
 * and handles debugging events such as breakpoints and single-step exceptions.
 *
 * @return int 0 if successful, 1 if CreateProcessW fails, -1 if encryption fails.
 */
int main() {
    License license;
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    char name[MAX_NAME_LENGTH];
    find_out_exe_file(name, MAX_NAME_LENGTH);
    char exe_file_name[MAX_PATH_LENGTH];
    get_exe_path(name, exe_file_name, sizeof(exe_file_name));
    printf("%s \n", exe_file_name);
    WCHAR commandLine[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, exe_file_name, -1, commandLine, MAX_PATH);

    if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return 1;
    }
    PEFormat file_fields(exe_file_name);
    std::map<ADDR_TYPE, ADDR_TYPE> breakpoints_address_map;
    read_block_addresses_from_binary(BLOCKS_FILE_NAME, breakpoints_address_map);
    SIZE_T breakpoints_size = breakpoints_address_map.size();
    ADDR_TYPE breakpoints_address[MAX_ADDRESSES];
    int i = 0;
    for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it) {
        breakpoints_address[i++] = it->first;
    }
    bool is_breakpoints_seted = false;
    DEBUG_EVENT de;
    DWORD continue_status = DBG_CONTINUE;
    ADDR_TYPE base_address = NULL;
    ResumeThread(pi.hThread);
    std::vector<ADDR_TYPE> call_addresses;
    read_call_addresses_from_binary(CALLS_ADDRESS_FILE_Name, call_addresses);


    while (TRUE) {
        BYTE l[57];
        SIZE_T t;
        continue_status = DBG_CONTINUE;
        if (!WaitForDebugEvent(&de, INFINITE)) {
            printf("WaitForDebugEvent failed (%d).\n", GetLastError());
            break;
        }
        if (!is_breakpoints_seted)
        {
            base_address = get_process_base_address(pi.hProcess);

            if (base_address)
            {

                for (ADDR_TYPE& address : file_fields.relocationAddresses)
                {
                    address += base_address;
                }
                is_breakpoints_seted = set_breakpoints(breakpoints_address, breakpoints_size, pi.hProcess, base_address);
                for (ADDR_TYPE addr : call_addresses)
                {
                    if (!get_start_block(addr, breakpoints_address_map))//if the addr is not encrypted
                    {
                        set_breakpoint(pi.hProcess, addr + base_address);
                    }
                }
            }
        }
#if _MODE_64
        CONTEXT context;
        GetThreadContext(pi.hThread, &context);
        ADDR_TYPE currentEip = context.Rip;
#else
        WOW64_CONTEXT context;
        context.ContextFlags = WOW64_CONTEXT_CONTROL;
        Wow64GetThreadContext(pi.hThread, &context);//very weird  values in context
        ADDR_TYPE currentEip = context.Eip;
#endif
        //print_debug_event(de);
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            context.EFlags &= ~0x100;  // Clear the trap flag
            ADDR_TYPE cur_virtual_address = currentEip - base_address;
            enc_part_of_block(pi, cur_virtual_address, license.key, file_fields, base_address, breakpoints_address_map);
#if _MODE_64
            SetThreadContext(pi.hThread, &context);
#else
            Wow64SetThreadContext(pi.hThread, &context);
#endif
            continue_status = DBG_CONTINUE;
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
#if _MODE_64
            currentEip = --context.Rip;
#else
            currentEip = --context.Eip;
#endif

            context.ContextFlags = CONTEXT_CONTROL;
            ADDR_TYPE cur_virtual_address = currentEip - base_address;
            if (std::find(call_addresses.begin(), call_addresses.end(), cur_virtual_address) != call_addresses.end())
            {
                restore_original_byte(pi.hProcess, currentEip);
                context.EFlags |= 0x100;  // Clear the trap flag
#if _MODE_64
                SetThreadContext(pi.hThread, &context);
#else
                Wow64SetThreadContext(pi.hThread, &context);
#endif
                continue_status = DBG_CONTINUE;
            }
            else if (breakpoints_address_map.find(cur_virtual_address) != breakpoints_address_map.end())
            {
                restore_original_byte(pi.hProcess, currentEip);
                SIZE_T block_size = breakpoints_address_map[cur_virtual_address] - cur_virtual_address;
                if (!encrypt_block_with_realloction(cur_virtual_address, block_size, pi, license, file_fields, base_address, breakpoints_address_map))
                {
                    printf("ERROR encrypt_block_with_realloction \n");
                    return -1;
                }
                for (auto it = call_addresses.begin(); it != call_addresses.end(); ++it)
                {
                    if (*it > cur_virtual_address and *it < breakpoints_address_map[cur_virtual_address])
                    {
                        if (!set_breakpoint(pi.hProcess, *it + base_address))
                        {
                            printf("could set breakpint in %p \n", *it);
                            return -1;
                        }
                        break;
                    }
                }
#if _MODE_64
                SetThreadContext(pi.hThread, &context);
#else
                Wow64SetThreadContext(pi.hThread, &context);
#endif
                continue_status = DBG_CONTINUE;

            }
            else
            {

            }

        }
        else
        {
#if _MODE_64
            CONTEXT context;
            GetThreadContext(pi.hThread, &context);
#else
            WOW64_CONTEXT context;
            Wow64GetThreadContext(pi.hThread, &context);
#endif
            context.ContextFlags = CONTEXT_CONTROL;
#if _MODE_64 == true
            ADDR_TYPE currentEip = context.Rip - 1;
#else
            ADDR_TYPE currentEip = context.Eip - 1;
#endif
        }


        if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continue_status)) {
            printf("ContinueDebugEvent failed (%d).\n", GetLastError());
            break;
        }

        if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("Process exited.\n");
            break;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
