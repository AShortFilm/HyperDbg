/**
 * @file HyperEvade.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Hyperevade function wrappers
 * @details
 *
 * @version 0.14
 * @date 2025-06-07
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

#define TRANSPARENT_INVALID_SYSCALL_NUMBER ((UINT32)~0u)

static PUCHAR
TransparentResolveRelativeJump(PUCHAR Address)
{
    for (UINT32 depth = 0; depth < 4; depth++)
    {
        if (Address[0] == 0xE9)
        {
            Address += 5 + *(INT32 *)(Address + 1);
        }
        else if (Address[0] == 0xEB)
        {
            Address += 2 + *(INT8 *)(Address + 1);
        }
        else
        {
            break;
        }
    }

    return Address;
}

static UINT32
TransparentDecodeSyscallNumber(PVOID Routine)
{
    if (Routine == NULL)
    {
        return TRANSPARENT_INVALID_SYSCALL_NUMBER;
    }

    __try
    {
        PUCHAR Code = TransparentResolveRelativeJump((PUCHAR)Routine);

        if (Code[0] == 0x4C && Code[1] == 0x8B && Code[2] == 0xD1)
        {
            Code += 3;
        }

        for (UINT32 offset = 0; offset < 16; offset++)
        {
            if (Code[offset] == 0xB8)
            {
                return *(UINT32 *)(Code + offset + 1);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return TRANSPARENT_INVALID_SYSCALL_NUMBER;
    }

    return TRANSPARENT_INVALID_SYSCALL_NUMBER;
}

static UINT32
TransparentResolveSyscallNumber(PCWSTR RoutineName)
{
    UNICODE_STRING RoutineString;
    RtlInitUnicodeString(&RoutineString, RoutineName);

    return TransparentDecodeSyscallNumber(MmGetSystemRoutineAddress(&RoutineString));
}

static VOID
TransparentPopulateSystemCallNumbers(SYSTEM_CALL_NUMBERS_INFORMATION * Info, BOOLEAN * AllRequiredResolved)
{
    RtlFillMemory(Info, sizeof(*Info), 0xFF);

    *AllRequiredResolved = TRUE;

    typedef struct _TRANSPARENT_SYSCALL_LOOKUP
    {
        UINT32 * Target;
        PCWSTR   RoutineName;
        BOOLEAN  Optional;
    } TRANSPARENT_SYSCALL_LOOKUP;

    const TRANSPARENT_SYSCALL_LOOKUP Lookups[] = {
        {&Info->SysNtQuerySystemInformation, L"ZwQuerySystemInformation", FALSE},
        {&Info->SysNtQuerySystemInformationEx, L"ZwQuerySystemInformationEx", TRUE},
        {&Info->SysNtSystemDebugControl, L"ZwSystemDebugControl", FALSE},
        {&Info->SysNtQueryAttributesFile, L"ZwQueryAttributesFile", FALSE},
        {&Info->SysNtOpenDirectoryObject, L"ZwOpenDirectoryObject", FALSE},
        {&Info->SysNtQueryDirectoryObject, L"ZwQueryDirectoryObject", FALSE},
        {&Info->SysNtQueryInformationProcess, L"ZwQueryInformationProcess", FALSE},
        {&Info->SysNtSetInformationProcess, L"ZwSetInformationProcess", FALSE},
        {&Info->SysNtQueryInformationThread, L"ZwQueryInformationThread", FALSE},
        {&Info->SysNtSetInformationThread, L"ZwSetInformationThread", FALSE},
        {&Info->SysNtOpenFile, L"ZwOpenFile", FALSE},
        {&Info->SysNtOpenKey, L"ZwOpenKey", FALSE},
        {&Info->SysNtOpenKeyEx, L"ZwOpenKeyEx", TRUE},
        {&Info->SysNtQueryValueKey, L"ZwQueryValueKey", FALSE},
        {&Info->SysNtEnumerateKey, L"ZwEnumerateKey", FALSE},
    };

    for (UINT32 i = 0; i < RTL_NUMBER_OF(Lookups); i++)
    {
        UNICODE_STRING RoutineString;
        RtlInitUnicodeString(&RoutineString, Lookups[i].RoutineName);

        UINT32 Number = TransparentResolveSyscallNumber(Lookups[i].RoutineName);
        *Lookups[i].Target = Number;

        if (Number == TRANSPARENT_INVALID_SYSCALL_NUMBER)
        {
            if (Lookups[i].Optional)
            {
                LogDebugInfo("Optional system routine %wZ is unavailable; continuing without it for transparency mode.",
                             &RoutineString);
            }
            else
            {
                LogWarning("Warning, unable to resolve syscall number for %wZ; transparency coverage might be limited.",
                           &RoutineString);
                *AllRequiredResolved = FALSE;
            }
        }
    }
}

/**
 * @brief Wrapper for hiding debugger on transparent-mode (activate transparent-mode)
 *
 * @param HyperevadeCallbacks
 * @param TransparentModeRequest
 *
 * @return BOOLEAN
 */
BOOLEAN
TransparentHideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    HYPEREVADE_CALLBACKS HyperevadeCallbacks = {0};

    //
    // *** Fill the callbacks ***
    //

    //
    // Fill the callbacks for using hyperlog in hyperevade
    // We use the callbacks directly to avoid two calls to the same function
    //
    HyperevadeCallbacks.LogCallbackPrepareAndSendMessageToQueueWrapper = g_Callbacks.LogCallbackPrepareAndSendMessageToQueueWrapper;
    HyperevadeCallbacks.LogCallbackSendMessageToQueue                  = g_Callbacks.LogCallbackSendMessageToQueue;
    HyperevadeCallbacks.LogCallbackSendBuffer                          = g_Callbacks.LogCallbackSendBuffer;
    HyperevadeCallbacks.LogCallbackCheckIfBufferIsFull                 = g_Callbacks.LogCallbackCheckIfBufferIsFull;

    //
    // Memory callbacks
    //
    HyperevadeCallbacks.CheckAccessValidityAndSafety               = CheckAccessValidityAndSafety;
    HyperevadeCallbacks.MemoryMapperReadMemorySafeOnTargetProcess  = MemoryMapperReadMemorySafeOnTargetProcess;
    HyperevadeCallbacks.MemoryMapperWriteMemorySafeOnTargetProcess = MemoryMapperWriteMemorySafeOnTargetProcess;

    //
    // Common callbacks
    //
    HyperevadeCallbacks.CommonGetProcessNameFromProcessControlBlock = CommonGetProcessNameFromProcessControlBlock;

    //
    // System call callbacks
    //
    HyperevadeCallbacks.SyscallCallbackSetTrapFlagAfterSyscall = SyscallCallbackSetTrapFlagAfterSyscall;

    //
    // VMX callbacks
    //
    HyperevadeCallbacks.HvHandleTrapFlag             = HvHandleTrapFlag;
    HyperevadeCallbacks.EventInjectGeneralProtection = EventInjectGeneralProtection;

    //
    // Initialize the syscall callback mechanism from hypervisor
    //
    if (!SyscallCallbackInitialize())
    {
        TransparentModeRequest->KernelStatus = DEBUGGER_ERROR_UNABLE_TO_HIDE_OR_UNHIDE_DEBUGGER;
        return FALSE;
    }

    //
    // Call the hyperevade hide debugger function
    //
    if (TransparentHideDebugger(&HyperevadeCallbacks, TransparentModeRequest))
    {
        //
        // Status is set within the transparent mode (hyperevade) module
        //
        g_CheckForFootprints = TRUE;
        return TRUE;
    }
    else
    {
        //
        // Status is set within the transparent mode (hyperevade) module
        //
        g_CheckForFootprints = FALSE;
        return FALSE;
    }
}

/**
 * @brief Deactivate transparent-mode
 * @param TransparentModeRequest
 *
 * @return BOOLEAN
 */
BOOLEAN
TransparentUnhideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    //
    // Unitialize the syscall callback mechanism from hypervisor
    //
    SyscallCallbackUninitialize();

    if (TransparentUnhideDebugger())
    {
        //
        // Unset transparent mode for the VMM module
        //
        g_CheckForFootprints = FALSE;

        if (TransparentModeRequest != NULL)
        {
            TransparentModeRequest->KernelStatus = DEBUGGER_OPERATION_WAS_SUCCESSFUL;
        }

        return TRUE;
    }
    else
    {
        if (TransparentModeRequest != NULL)
        {
            TransparentModeRequest->KernelStatus = DEBUGGER_ERROR_DEBUGGER_ALREADY_UNHIDE;
        }
        return FALSE;
    }
}

/**
 * @brief Enable transparent-mode with default settings at startup.
 *
 * @return BOOLEAN
 */
BOOLEAN
TransparentEnableDefaultMode()
{
#if ActivateHyperEvadeProject != TRUE
    return TRUE;
#else
    DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE Request = {0};
    BOOLEAN                                     AllRequiredResolved;

    TransparentPopulateSystemCallNumbers(&Request.SystemCallNumbersInformation, &AllRequiredResolved);

    Request.IsHide = TRUE;

    if (TransparentHideDebuggerWrapper(&Request))
    {
        if (!AllRequiredResolved)
        {
            LogWarning("Transparent mode enabled automatically with partial syscall coverage.");
        }
        else
        {
            LogDebugInfo("Transparent mode enabled automatically.");
        }

        return TRUE;
    }

    if (Request.KernelStatus == DEBUGGER_ERROR_DEBUGGER_ALREADY_HIDE)
    {
        return TRUE;
    }

    LogWarning("Err, automatic transparent-mode enable failed (status: 0x%x)", Request.KernelStatus);

    return FALSE;
#endif
}
