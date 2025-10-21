/**
 * @file StealthyMemory.c
 * @brief Stealthy memory access helpers that operate from VMX root
 */
#include "pch.h"
#include "interface/StealthyMemory.h"

_Use_decl_annotations_
NTSTATUS
VmmStealthyReadProcessMemory(UINT32 ProcessId, UINT64 VirtualAddress, PVOID Buffer, SIZE_T Size)
{
    if (Buffer == NULL || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    CR3_TYPE ProcessCr3 = LayoutGetCr3ByProcessId(ProcessId);
    if (ProcessCr3.Flags == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T BytesRead = 0;

    while (BytesRead < Size)
    {
        UINT64 CurrentVa  = VirtualAddress + BytesRead;
        SIZE_T PageOffset = (SIZE_T)(CurrentVa & 0xFFFULL);
        SIZE_T Remaining  = Size - BytesRead;
        SIZE_T ChunkSize  = PAGE_SIZE - PageOffset;
        if (ChunkSize > Remaining)
        {
            ChunkSize = Remaining;
        }

        UINT64 PhysicalAddress = VirtualAddressToPhysicalAddressByProcessCr3((PVOID)CurrentVa, ProcessCr3);
        if (PhysicalAddress == 0)
        {
            return STATUS_INVALID_ADDRESS;
        }

        if (!MemoryMapperReadMemorySafeByPhysicalAddress(PhysicalAddress,
                                                         (UINT64)((PUCHAR)Buffer + BytesRead),
                                                         ChunkSize))
        {
            return STATUS_UNSUCCESSFUL;
        }

        BytesRead += ChunkSize;
    }

    return STATUS_SUCCESS;
}
