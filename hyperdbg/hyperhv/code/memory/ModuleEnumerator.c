/**
 * @file ModuleEnumerator.c
 * @brief VMX-root process module enumeration helpers
 */
#include "pch.h"
#include "interface/StealthyMemory.h"
#include "memory/ModuleEnumerator.h"

// Declare kernel helpers that might not be prototyped in WDK headers
extern PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
extern PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

static NTSTATUS ReadRemoteMemory32(UINT32 Pid, UINT32 Va, PVOID Buffer, SIZE_T Size)
{
    return VmmStealthyReadProcessMemory(Pid, (UINT64)Va, Buffer, Size);
}

static NTSTATUS ReadRemoteMemory64(UINT32 Pid, UINT64 Va, PVOID Buffer, SIZE_T Size)
{
    return VmmStealthyReadProcessMemory(Pid, Va, Buffer, Size);
}

static UINT32 MinU32(UINT32 a, UINT32 b) { return a < b ? a : b; }
static SIZE_T MinSize(SIZE_T a, SIZE_T b) { return a < b ? a : b; }

static VOID CopyUnicodeFromRemote32(UINT32 Pid, const UNICODE_STRING32 * Src, WCHAR * Dest, UINT32 DestChars)
{
    if (DestChars == 0)
        return;

    RtlZeroMemory(Dest, DestChars * sizeof(WCHAR));

    if (Src == NULL || Src->Buffer == 0 || Src->Length == 0)
        return;

    UINT32 BytesToRead = MinU32(Src->Length, (DestChars - 1) * (UINT32)sizeof(WCHAR));
    if (BytesToRead == 0)
        return;

    (void)ReadRemoteMemory32(Pid, Src->Buffer, Dest, BytesToRead);
    Dest[BytesToRead / sizeof(WCHAR)] = L'\0';
}

static VOID CopyUnicodeFromRemote64(UINT32 Pid, const UNICODE_STRING * Src, WCHAR * Dest, UINT32 DestChars)
{
    if (DestChars == 0)
        return;

    RtlZeroMemory(Dest, DestChars * sizeof(WCHAR));

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0)
        return;

    SIZE_T BytesToRead = MinSize(Src->Length, (DestChars - 1) * sizeof(WCHAR));
    if (BytesToRead == 0)
        return;

    (void)ReadRemoteMemory64(Pid, (UINT64)Src->Buffer, Dest, BytesToRead);
    Dest[BytesToRead / sizeof(WCHAR)] = L'\0';
}

_Use_decl_annotations_
NTSTATUS
VmmEnumerateProcessModules(UINT32 ProcessId, MODULE_INFO * ModuleList, UINT32 * ModuleCount)
{
    if (ModuleCount == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    UINT32 OutCapacity = (ModuleList != NULL) ? *ModuleCount : 0;
    *ModuleCount       = 0;

    // Get CR3 to verify process exists
    CR3_TYPE Cr3 = LayoutGetCr3ByProcessId(ProcessId);
    if (Cr3.Flags == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS Eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Eproc)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // Determine WoW64 (32-bit) process
    BOOLEAN IsWow64 = (PsGetProcessWow64Process != NULL && PsGetProcessWow64Process(Eproc) != NULL) ? TRUE : FALSE;

    NTSTATUS Status = STATUS_SUCCESS;

    if (IsWow64)
    {
        // 32-bit path
        UINT64 PebUserVa = (UINT64)PsGetProcessWow64Process(Eproc);
        if (PebUserVa == 0)
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        PEB32_MIN Peb32 = {0};
        if (!NT_SUCCESS(ReadRemoteMemory64(ProcessId, PebUserVa, &Peb32, sizeof(Peb32))))
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        UINT32 LdrAddr = Peb32.Ldr;
        if (LdrAddr == 0)
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        PEB_LDR_DATA32_MIN Ldr = {0};
        if (!NT_SUCCESS(ReadRemoteMemory32(ProcessId, LdrAddr, &Ldr, sizeof(Ldr))))
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        UINT32 Head = LdrAddr + FIELD_OFFSET(PEB_LDR_DATA32_MIN, InLoadOrderModuleList);
        UINT32 List = Ldr.InLoadOrderModuleList.Flink;

        UINT32 Safety = 0;
        while (List != 0 && List != Head && Safety++ < 2048)
        {
            UINT32 EntryAddr = List - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32_MIN, InLoadOrderLinks);

            LDR_DATA_TABLE_ENTRY32_MIN Entry = {0};
            if (!NT_SUCCESS(ReadRemoteMemory32(ProcessId, EntryAddr, &Entry, sizeof(Entry))))
            {
                break;
            }

            if (ModuleList != NULL && *ModuleCount < OutCapacity)
            {
                PMODULE_INFO Out = &ModuleList[*ModuleCount];
                RtlZeroMemory(Out, sizeof(*Out));
                Out->BaseAddress = (UINT64)Entry.DllBase;
                Out->Size        = (UINT64)Entry.SizeOfImage;
                CopyUnicodeFromRemote32(ProcessId, &Entry.BaseDllName, Out->ModuleName, MODULE_INFO_MAX_CHARS);
                CopyUnicodeFromRemote32(ProcessId, &Entry.FullDllName, Out->ModulePath, MODULE_INFO_MAX_CHARS);
            }

            (*ModuleCount)++;
            List = Entry.InLoadOrderLinks.Flink;
        }
    }
    else
    {
        // 64-bit path
        UINT64 PebUserVa = (UINT64)PsGetProcessPeb(Eproc);
        if (PebUserVa == 0)
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        PEB64_MIN Peb = {0};
        if (!NT_SUCCESS(ReadRemoteMemory64(ProcessId, PebUserVa, &Peb, sizeof(Peb))))
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        UINT64 LdrAddr = (UINT64)Peb.Ldr;
        if (LdrAddr == 0)
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        PEB_LDR_DATA64_MIN Ldr = {0};
        if (!NT_SUCCESS(ReadRemoteMemory64(ProcessId, LdrAddr, &Ldr, sizeof(Ldr))))
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        UINT64 Head = LdrAddr + FIELD_OFFSET(PEB_LDR_DATA64_MIN, ModuleListLoadOrder);
        UINT64 List = (UINT64)Ldr.ModuleListLoadOrder.Flink;

        UINT32 Safety = 0;
        while (List != 0 && List != Head && Safety++ < 4096)
        {
            UINT64 EntryAddr = List - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64_MIN, InLoadOrderModuleList);

            LDR_DATA_TABLE_ENTRY64_MIN Entry = {0};
            if (!NT_SUCCESS(ReadRemoteMemory64(ProcessId, EntryAddr, &Entry, sizeof(Entry))))
            {
                break;
            }

            if (ModuleList != NULL && *ModuleCount < OutCapacity)
            {
                PMODULE_INFO Out = &ModuleList[*ModuleCount];
                RtlZeroMemory(Out, sizeof(*Out));
                Out->BaseAddress = (UINT64)Entry.DllBase;
                Out->Size        = (UINT64)Entry.SizeOfImage;
                CopyUnicodeFromRemote64(ProcessId, &Entry.BaseDllName, Out->ModuleName, MODULE_INFO_MAX_CHARS);
                CopyUnicodeFromRemote64(ProcessId, &Entry.FullDllName, Out->ModulePath, MODULE_INFO_MAX_CHARS);
            }

            (*ModuleCount)++;
            List = (UINT64)Entry.InLoadOrderModuleList.Flink;
        }
    }

    Status = STATUS_SUCCESS;

Cleanup:
    if (Eproc)
    {
        ObDereferenceObject(Eproc);
    }

    return Status;
}

_Use_decl_annotations_
UINT64
VmmGetModuleBaseAddress(UINT32 ProcessId, const WCHAR * ModuleName)
{
    if (ModuleName == NULL)
    {
        return 0;
    }

    // Get CR3 to verify process exists
    CR3_TYPE Cr3 = LayoutGetCr3ByProcessId(ProcessId);
    if (Cr3.Flags == 0)
    {
        return 0;
    }

    PEPROCESS Eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Eproc)))
    {
        return 0;
    }

    BOOLEAN IsWow64 = (PsGetProcessWow64Process != NULL && PsGetProcessWow64Process(Eproc) != NULL) ? TRUE : FALSE;

    UINT64 Result = 0;

    if (IsWow64)
    {
        UINT64 PebUserVa = (UINT64)PsGetProcessWow64Process(Eproc);
        if (PebUserVa)
        {
            PEB32_MIN Peb32 = {0};
            if (NT_SUCCESS(ReadRemoteMemory64(ProcessId, PebUserVa, &Peb32, sizeof(Peb32))))
            {
                UINT32 LdrAddr = Peb32.Ldr;
                if (LdrAddr)
                {
                    PEB_LDR_DATA32_MIN Ldr = {0};
                    if (NT_SUCCESS(ReadRemoteMemory32(ProcessId, LdrAddr, &Ldr, sizeof(Ldr))))
                    {
                        UINT32 Head = LdrAddr + FIELD_OFFSET(PEB_LDR_DATA32_MIN, InLoadOrderModuleList);
                        UINT32 List = Ldr.InLoadOrderModuleList.Flink;
                        UINT32 Safety = 0;
                        while (List != 0 && List != Head && Safety++ < 2048)
                        {
                            UINT32 EntryAddr = List - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32_MIN, InLoadOrderLinks);
                            LDR_DATA_TABLE_ENTRY32_MIN Entry = {0};
                            if (!NT_SUCCESS(ReadRemoteMemory32(ProcessId, EntryAddr, &Entry, sizeof(Entry))))
                                break;

                            WCHAR Name[MODULE_INFO_MAX_CHARS] = {0};
                            CopyUnicodeFromRemote32(ProcessId, &Entry.BaseDllName, Name, MODULE_INFO_MAX_CHARS);
                            if (VmFuncVmxCompatibleWcscmp(Name, ModuleName) == 0)
                            {
                                Result = (UINT64)Entry.DllBase;
                                break;
                            }

                            List = Entry.InLoadOrderLinks.Flink;
                        }
                    }
                }
            }
        }
    }
    else
    {
        UINT64 PebUserVa = (UINT64)PsGetProcessPeb(Eproc);
        if (PebUserVa)
        {
            PEB64_MIN Peb = {0};
            if (NT_SUCCESS(ReadRemoteMemory64(ProcessId, PebUserVa, &Peb, sizeof(Peb))))
            {
                UINT64 LdrAddr = (UINT64)Peb.Ldr;
                if (LdrAddr)
                {
                    PEB_LDR_DATA64_MIN Ldr = {0};
                    if (NT_SUCCESS(ReadRemoteMemory64(ProcessId, LdrAddr, &Ldr, sizeof(Ldr))))
                    {
                        UINT64 Head = LdrAddr + FIELD_OFFSET(PEB_LDR_DATA64_MIN, ModuleListLoadOrder);
                        UINT64 List = (UINT64)Ldr.ModuleListLoadOrder.Flink;
                        UINT32 Safety = 0;
                        while (List != 0 && List != Head && Safety++ < 4096)
                        {
                            UINT64 EntryAddr = List - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64_MIN, InLoadOrderModuleList);
                            LDR_DATA_TABLE_ENTRY64_MIN Entry = {0};
                            if (!NT_SUCCESS(ReadRemoteMemory64(ProcessId, EntryAddr, &Entry, sizeof(Entry))))
                                break;

                            WCHAR Name[MODULE_INFO_MAX_CHARS] = {0};
                            CopyUnicodeFromRemote64(ProcessId, &Entry.BaseDllName, Name, MODULE_INFO_MAX_CHARS);
                            if (VmFuncVmxCompatibleWcscmp(Name, ModuleName) == 0)
                            {
                                Result = (UINT64)Entry.DllBase;
                                break;
                            }

                            List = (UINT64)Entry.InLoadOrderModuleList.Flink;
                        }
                    }
                }
            }
        }
    }

    if (Eproc)
    {
        ObDereferenceObject(Eproc);
    }

    return Result;
}
