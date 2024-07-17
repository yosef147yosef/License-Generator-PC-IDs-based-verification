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
                ADDR_TYPE addr_called = NULL;
#if _MODE_64
                Register64 reg = identify_call_register(pi.hProcess, currentEip);
                switch (reg) {
                case Register64::RAX:
                    addr_called = context.Rax;
                    break;
                case Register64::RCX:
                    addr_called = context.Rcx;
                    break;
                case Register64::RDX:
                    addr_called = context.Rdx;
                    break;
                case Register64::RBX:
                    addr_called = context.Rbx;
                    break;
                case Register64::RSP:
                    addr_called = context.Rsp;
                    break;
                case Register64::RBP:
                    addr_called = context.Rbp;
                    break;
                case Register64::RSI:
                    addr_called = context.Rsi;
                    break;
                case Register64::RDI:
                    addr_called = context.Rdi;
                    break;
                case Register64::R8:
                    addr_called = context.R8;
                    break;
                case Register64::R9:
                    addr_called = context.R9;
                    break;
                case Register64::R10:
                    addr_called = context.R10;
                    break;
                case Register64::R11:
                    addr_called = context.R11;
                    break;
                case Register64::R12:
                    addr_called = context.R12;
                    break;
                case Register64::R13:
                    addr_called = context.R13;
                    break;
                case Register64::R14:
                    addr_called = context.R14;
                    break;
                case Register64::R15:
                    addr_called = context.R15;
                    break;
                default:
                    printf("ERROR couldn't find the right register\n");
                    break;
            }
#else
                Register32 reg = identify_call_register(pi.hProcess, currentEip);
                switch (reg) {
                case Register32::EAX: 
                    addr_called = context.Eax;
                    break;
                case Register32::ECX: 
                    addr_called = context.Ecx;
                    break;
                case Register32::EDX: 
                    addr_called = context.Edx;
                    break;
                case Register32::EBX: 
                    addr_called = context.Ebx;
                    break;
                case Register32::ESP: 
                    addr_called = context.Esp;
                    break;
                case Register32::EBP: 
                    addr_called = context.Ebp;
                    break;
                case Register32::ESI: 
                    addr_called = context.Esi;
                    break;
                case Register32::EDI:
                    addr_called = context.Edi;
                    break;
                default: 
                    printf("ERROR couldnt find the right register\n");
                }
#endif
                if (addr_called)
                {
                    for (const auto breakpoint : breakpoints_address_map)
                    {
                        ADDR_TYPE startAddress = breakpoint.first;
                        ADDR_TYPE  endAddress = breakpoint.second;
                        if (addr_called > startAddress and addr_called < endAddress)
                        {
                            if (!encrypt_block_with_realloction(startAddress, endAddress - startAddress, pi.hProcess, license.key, file_fields, currentEip, base_address))
                            {
                                printf("ERROR encrypt_block_with_realloction \n");
                            }
                            break;

                        }
                    }

                }
#if _MODE_64
                SetThreadContext(pi.hThread, &context);
#else
                Wow64SetThreadContext(pi.hThread, &context);
#endif
            }
            else if (breakpoints_address_map.find(cur_virtual_address) != breakpoints_address_map.end())
            {
                printf("Breakpoint hit at %p\n", (LPVOID)currentEip);
                restore_original_byte(pi.hProcess, currentEip);
                SIZE_T block_size = breakpoints_address_map[cur_virtual_address] - cur_virtual_address;

                if (!encrypt_block_with_realloction(cur_virtual_address,block_size,pi.hProcess, license.key, file_fields, currentEip, base_address))
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
