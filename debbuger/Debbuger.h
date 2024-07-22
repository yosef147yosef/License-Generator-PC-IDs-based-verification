#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h> 
#include <map>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "Raw_Bytes_Helper.h"
#include "Mode.h"
typedef struct {
    ADDR_TYPE address;
    BYTE originalByte;
} Breakpoint;

Breakpoint breakpoints[MAX_BREAKPOINTS];
int breakpoint_count = 0;
BOOL set_breakpoint(HANDLE hProcess, ADDR_TYPE address) {
    if (breakpoint_count >= MAX_BREAKPOINTS) {
        printf("Maximum number of breakpoints reached.\n");
        return FALSE;
    }

    BYTE originalByte[20];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPVOID)address, &originalByte, 20, &bytesRead)) {
        printf("Failed to read memory at %p\n", (LPVOID)address);
        return FALSE;
    }

    BYTE int3[] = { 0xCC };
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, &int3, 1, &bytesWritten)) {
        printf("Failed to write breakpoint at %p\n", (LPVOID)address);
        return FALSE;
    }
    //print_byte_array_as_hex(originalByte, bytesRead);
    breakpoints[breakpoint_count].address = address;
    breakpoints[breakpoint_count].originalByte = originalByte[0];
    breakpoint_count++;
    return TRUE;
}

bool set_breakpoints(ADDR_TYPE address[], SIZE_T address_size, HANDLE hprocess, ADDR_TYPE base_address)
{
    if (base_address == NULL) {
        printf("Failed to get process base address.\n");
        return false;
    }
    for (int i = 0; i < address_size; i++)
    {
        ADDR_TYPE target_address = address[i] + base_address;
        if (!set_breakpoint(hprocess, (base_address + address[i]))) {
            printf("Failed to set breakpoint at address %p.\n", (LPVOID)target_address);
            return false;
        }
    }
    return true;
}

bool restore_original_byte(HANDLE hProcess, ADDR_TYPE address) {
    for (int i = 0; i < breakpoint_count; i++) {
        if (breakpoints[i].address == address) {
            SIZE_T bytesWritten;
            WriteProcessMemory(hProcess, (LPVOID)address, &breakpoints[i].originalByte, 1, &bytesWritten);
            return true;
        }
    }
    return false;;
}
void print_debug_event(DEBUG_EVENT de) {
    switch (de.dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT: {
        printf("Exception: ");
        switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            printf("EXCEPTION_ACCESS_VIOLATION\n");
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            printf("EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
            break;
        case EXCEPTION_BREAKPOINT:
            printf("EXCEPTION_BREAKPOINT\n");
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            printf("EXCEPTION_DATATYPE_MISALIGNMENT\n");
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            printf("EXCEPTION_FLT_DENORMAL_OPERAND\n");
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            printf("EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            printf("EXCEPTION_FLT_INEXACT_RESULT\n");
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            printf("EXCEPTION_FLT_INVALID_OPERATION\n");
            break;
        case EXCEPTION_FLT_OVERFLOW:
            printf("EXCEPTION_FLT_OVERFLOW\n");
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            printf("EXCEPTION_FLT_STACK_CHECK\n");
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            printf("EXCEPTION_FLT_UNDERFLOW\n");
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            printf("EXCEPTION_ILLEGAL_INSTRUCTION\n");
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            printf("EXCEPTION_IN_PAGE_ERROR\n");
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            printf("EXCEPTION_INT_DIVIDE_BY_ZERO\n");
            break;
        case EXCEPTION_INT_OVERFLOW:
            printf("EXCEPTION_INT_OVERFLOW\n");
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            printf("EXCEPTION_INVALID_DISPOSITION\n");
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            printf("EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            printf("EXCEPTION_PRIV_INSTRUCTION\n");
            break;
        case EXCEPTION_SINGLE_STEP:
            printf("EXCEPTION_SINGLE_STEP\n");
            break;
        case EXCEPTION_STACK_OVERFLOW:
            printf("EXCEPTION_STACK_OVERFLOW\n");
            break;
        default:
            printf("Unknown exception code: 0x%08X\n", de.u.Exception.ExceptionRecord.ExceptionCode);
            break;
        }
        break;
    }
    case CREATE_THREAD_DEBUG_EVENT:
        printf("CreateThread\n");
        break;
    case CREATE_PROCESS_DEBUG_EVENT:
        printf("CreateProcess\n");
        break;
    case EXIT_THREAD_DEBUG_EVENT:
        printf("ExitThread\n");
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        printf("ExitProcess\n");
        break;
    case LOAD_DLL_DEBUG_EVENT:
        printf("LoadDll\n");
        break;
    case UNLOAD_DLL_DEBUG_EVENT:
        printf("UnloadDll\n");
        break;
    case OUTPUT_DEBUG_STRING_EVENT:
        printf("OutputDebugString\n");
        break;
    case RIP_EVENT:
        printf("RipEvent\n");
        break;
    default:
        printf("Unknown event\n");
        break;
    }
}


