/**
 * @file StealthyMemory.h
 * @brief Stealthy memory access helpers that operate from VMX root
 */
#pragma once

#include "SDK/HyperDbgSdk.h"

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS
VmmStealthyReadProcessMemory(_In_ UINT32 ProcessId,
                             _In_ UINT64 VirtualAddress,
                             _Out_writes_bytes_(Size) PVOID Buffer,
                             _In_ SIZE_T Size);

#ifdef __cplusplus
}
#endif
