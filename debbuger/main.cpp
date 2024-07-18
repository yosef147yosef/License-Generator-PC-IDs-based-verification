#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h> 
#include <map>

#include <stdbool.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "Debbuger.h"
#include "Get_Reallocations.h"
#include <set>
#include "Call_insturction_handler.h"
#include <algorithm>
#include "Key_Gen.h"
int main() {
    License license;
    BYTE key[16] = { 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a' };
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    char exe_file_name[] =EXE_FILE_NAME;
    WCHAR commandLine[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, exe_file_name, -1, commandLine, MAX_PATH);

    if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return 1;
    }
    PEFormat file_fields(exe_file_name);
    printf("Started debugging process %d\n", pi.dwProcessId);
    std::map<ADDR_TYPE, ADDR_TYPE> breakpoints_address_map;

    read_block_addresses_from_binary(BLOCKS_FILE_NAME, breakpoints_address_map);
    SIZE_T breakpoints_size = breakpoints_address_map.size();
    ADDR_TYPE breakpoints_address[MAX_ADDRESSES];
    int i = 0;
    for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it) {
        breakpoints_address[i++] = it->first;
        printf("% p ", breakpoints_address[i - 1]);
    }
    bool is_breakpoints_seted = false;
    DEBUG_EVENT de;
    DWORD continue_status = DBG_CONTINUE;
    ADDR_TYPE base_address = NULL;
    ResumeThread(pi.hThread);
    bool want_to_debbug = false;
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
                is_breakpoints_seted &=  set_breakpoints(call_addresses.data(), call_addresses.size(), pi.hProcess, base_address);
            }
        }
        print_debug_event(de);
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
#if _MODE_64
        CONTEXT context;
        GetThreadContext(pi.hThread, &context);
        ADDR_TYPE currentEip = context.Rip;
#else
        WOW64_CONTEXT context;
        Wow64GetThreadContext(pi.hThread, &context);
        ADDR_TYPE currentEip = context.Eip;
        context.EFlags &= ~0x100;  // Clear the trap flag
#endif
        ADDR_TYPE cur_virtual_address = currentEip - base_address;
        for (auto it = breakpoints_address_map.begin(); it != breakpoints_address_map.end(); ++it) 
        {
            if (cur_virtual_address > it->first and cur_virtual_address < it->second)
            {
                if (!encrypt_block_with_realloction(cur_virtual_address, it->second - it->first, pi, key, file_fields, currentEip, base_address))
                {
                    printf("ERROR coundl decrypt %p ", cur_virtual_address + file_fields.imageBase);
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
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
#if _MODE_64
            CONTEXT context;
            GetThreadContext(pi.hThread, &context);
            ADDR_TYPE currentEip = --context.Rip;
#else
            WOW64_CONTEXT context;
            Wow64GetThreadContext(pi.hThread, &context);
            ADDR_TYPE currentEip = --context.Eip;
#endif
            context.ContextFlags = CONTEXT_CONTROL;
            ADDR_TYPE cur_virtual_address = currentEip - base_address;
            printf("%p \n ", cur_virtual_address);

            if ( std::find(call_addresses.begin() , call_addresses.end() , cur_virtual_address) !=call_addresses.end())
            {

                restore_original_byte(pi.hProcess, currentEip);
                context.EFlags |= 0x100;  // 0x100 is the trap flag
#if _MODE_64
                SetThreadContext(pi.hThread, &context);
#else
                Wow64SetThreadContext(pi.hThread, &context);
#endif
                continue_status = DBG_CONTINUE;
            }
            else if (breakpoints_address_map.find(cur_virtual_address) != breakpoints_address_map.end())
            {
                printf("Breakpoint hit at %p\n", (LPVOID)currentEip);
                restore_original_byte(pi.hProcess, currentEip);
                SIZE_T block_size = breakpoints_address_map[cur_virtual_address] - cur_virtual_address;

                if (!encrypt_block_with_realloction(cur_virtual_address,block_size,pi.hProcess, key, file_fields, currentEip, base_address))
                {
                    printf("ERROR encrypt_block_with_realloction \n");
                }
                //set_breakpoint(pi.hProcess, (ADDR_TYPE)0x00C21BE1);
                want_to_debbug = true;
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
            ADDR_TYPE currentEip = context.Rip-1;
#else
            ADDR_TYPE currentEip = context.Eip-1;
#endif
            BYTE l[30];
            SIZE_T t;
            ReadProcessMemory(pi.hProcess, (LPVOID)(currentEip-20), l, 30, &t);
            print_byte_array_as_hex(l, 30);
            printf("ERROR in :: eip : %p \n", currentEip - base_address);
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
