/**
 * @file ModuleEnumerator.h
 * @brief VMX-root process module enumeration helpers
 */
#pragma once

#include "SDK/HyperDbgSdk.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MODULE_INFO_MAX_CHARS 260

typedef struct _MODULE_INFO {
    UINT64 BaseAddress;
    UINT64 Size;
    WCHAR  ModuleName[MODULE_INFO_MAX_CHARS];
    WCHAR  ModulePath[MODULE_INFO_MAX_CHARS];
} MODULE_INFO, *PMODULE_INFO;

// 32-bit UNICODE_STRING for WoW64 processes
#ifndef _UNICODE_STRING32_DEFINED
#define _UNICODE_STRING32_DEFINED
typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    UINT32 Buffer; // 32-bit pointer
} UNICODE_STRING32, *PUNICODE_STRING32;
#endif

// Minimal PEB/LDR definitions required for enumeration
// 64-bit
typedef struct _PEB_LDR_DATA64_MIN {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY ModuleListLoadOrder;
    LIST_ENTRY ModuleListMemoryOrder;
    LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA64_MIN, *PPEB_LDR_DATA64_MIN;

typedef struct _PEB64_MIN {
    BYTE                        Reserved1[2];
    BYTE                        BeingDebugged;
    BYTE                        Reserved2[1];
    PVOID                       Reserved3[2];
    PPEB_LDR_DATA64_MIN         Ldr;
} PEB64_MIN, *PPEB64_MIN;

// 32-bit
typedef struct _PEB_LDR_DATA32_MIN {
    ULONG        Length;
    UCHAR        Initialized;
    ULONG        SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32_MIN, *PPEB_LDR_DATA32_MIN;

typedef struct _PEB32_MIN {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr; // PPEB_LDR_DATA32_MIN
} PEB32_MIN, *PPEB32_MIN;

// LDR entries
typedef struct _LDR_DATA_TABLE_ENTRY64_MIN {
    LIST_ENTRY     InLoadOrderModuleList;
    LIST_ENTRY     InMemoryOrderModuleList;
    LIST_ENTRY     InInitializationOrderModuleList;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY64_MIN, *PLDR_DATA_TABLE_ENTRY64_MIN;

typedef struct _LDR_DATA_TABLE_ENTRY32_MIN {
    LIST_ENTRY32     InLoadOrderLinks;
    LIST_ENTRY32     InMemoryOrderLinks;
    LIST_ENTRY32     InInitializationOrderLinks;
    ULONG            DllBase;
    ULONG            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32_MIN, *PLDR_DATA_TABLE_ENTRY32_MIN;

// Public interfaces
NTSTATUS
VmmEnumerateProcessModules(_In_ UINT32 ProcessId,
                           _Out_writes_opt_(*ModuleCount) MODULE_INFO * ModuleList,
                           _Inout_ UINT32 * ModuleCount);

UINT64
VmmGetModuleBaseAddress(_In_ UINT32 ProcessId, _In_z_ const WCHAR * ModuleName);

#ifdef __cplusplus
}
#endif
