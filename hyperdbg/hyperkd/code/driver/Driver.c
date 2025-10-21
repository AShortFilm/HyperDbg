/**
 * @file Driver.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief The project entry
 * @details This file contains major functions and all the interactions
 * with usermode codes are managed from here.
 * e.g debugger commands and extension commands
 * @version 0.1
 * @date 2020-04-10
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

typedef struct _HYPERKD_DEVICE_EXTENSION
{
    UNICODE_STRING DosDeviceName;
    WCHAR          DosDeviceNameBuffer[64];
} HYPERKD_DEVICE_EXTENSION, *PHYPERKD_DEVICE_EXTENSION;

/**
 * @brief Main Driver Entry in the case of driver load
 *
 * @param DriverObject
 * @param RegistryPath
 * @return NTSTATUS
 */
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS       Ntstatus      = STATUS_SUCCESS;
    UINT64         Index         = 0;
    PDEVICE_OBJECT DeviceObject  = NULL;
    UNICODE_STRING DriverName    = {0};
    UNICODE_STRING DosDeviceName = {0};

    //
    // Opt-in to using non-executable pool memory on Windows 8 and later.
    // https://msdn.microsoft.com/en-us/library/windows/hardware/hh920402(v=vs.85).aspx
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Compose randomized device names to reduce static detectability with retry to avoid rare collisions
    // Randomize both the leaf identifier and the DOS device namespace (\DosDevices vs. \??)
    //
    ULONG seed = (ULONG)(__rdtsc() ^ (ULONG)(ULONG_PTR)DriverObject);

    WCHAR DeviceNameBuffer[64]    = {0};
    WCHAR DosDeviceNameBuffer[64] = {0};

    RtlInitEmptyUnicodeString(&DriverName, DeviceNameBuffer, sizeof(DeviceNameBuffer));
    RtlInitEmptyUnicodeString(&DosDeviceName, DosDeviceNameBuffer, sizeof(DosDeviceNameBuffer));

    // Try several times to avoid name collisions if a stale instance exists
    for (int attempt = 0; attempt < 64; ++attempt)
    {
        // Random 16-bit suffix (hex) and random alphabetic base (6-12 chars)
        ULONG suffix = RtlRandomEx(&seed) & 0xFFFF;
        if (suffix == 0)
        {
            suffix = 0xA001;
        }

        WCHAR baseLeaf[24] = {0};
        UINT  baseLen      = 6 + (RtlRandomEx(&seed) % 7); // length in [6..12]
        for (UINT i = 0; i < baseLen && i < RTL_NUMBER_OF(baseLeaf) - 1; ++i)
        {
            ULONG r = RtlRandomEx(&seed) % 52; // [0..51]
            baseLeaf[i] = (WCHAR)((r < 26) ? (L'A' + r) : (L'a' + (r - 26)));
        }
        baseLeaf[baseLen] = L'\0';

        // Randomize DOS device namespace prefix
        const WCHAR* dosNsPrefix = (RtlRandomEx(&seed) & 1) ? L"\\??\\" : L"\\DosDevices\\";

        // Compose full names
        RtlUnicodeStringPrintf(&DriverName, L"\\Device\\%ws-%04X", baseLeaf, suffix);
        RtlUnicodeStringPrintf(&DosDeviceName, L"%ws%ws-%04X", dosNsPrefix, baseLeaf, suffix);

        //
        // Creating the device for interaction with user-mode
        //
        Ntstatus = IoCreateDevice(DriverObject,
                                  sizeof(HYPERKD_DEVICE_EXTENSION),
                                  &DriverName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &DeviceObject);

        if (!NT_SUCCESS(Ntstatus))
        {
            // Try another identifier on collision or other transient errors
            continue;
        }

        // Create a DOS symbolic link, retry on failure by deleting the created device
        NTSTATUS linkStatus = IoCreateSymbolicLink(&DosDeviceName, &DriverName);
        if (!NT_SUCCESS(linkStatus))
        {
            IoDeleteDevice(DeviceObject);
            DeviceObject = NULL;
            Ntstatus     = linkStatus;
            continue;
        }

        // Persist the composed DOS name in the device extension for cleanup
        PHYPERKD_DEVICE_EXTENSION Ext = (PHYPERKD_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
        RtlInitEmptyUnicodeString(&Ext->DosDeviceName, Ext->DosDeviceNameBuffer, sizeof(Ext->DosDeviceNameBuffer));
        RtlCopyUnicodeString(&Ext->DosDeviceName, &DosDeviceName);

        // Persist randomization artifacts for user-mode in the registry under ...\Services\<name>\Parameters
        if (RegistryPath && RegistryPath->Buffer)
        {
            HANDLE            ParametersKeyHandle = NULL;
            OBJECT_ATTRIBUTES Attributes;
            WCHAR             ParametersPathBuffer[512] = {0};
            UNICODE_STRING    ParametersPath;
            UNICODE_STRING    ValueName;
            ULONG             Disposition = 0;

            RtlInitEmptyUnicodeString(&ParametersPath, ParametersPathBuffer, sizeof(ParametersPathBuffer));
            RtlUnicodeStringPrintf(&ParametersPath, L"%wZ\\Parameters", RegistryPath);

            InitializeObjectAttributes(&Attributes, &ParametersPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            if (NT_SUCCESS(ZwCreateKey(&ParametersKeyHandle, KEY_ALL_ACCESS, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition)))
            {
                // Numeric suffix for backward compatibility
                RtlInitUnicodeString(&ValueName, L"DeviceSuffix");
                ZwSetValueKey(ParametersKeyHandle, &ValueName, 0, REG_DWORD, &suffix, sizeof(suffix));

                // Persist the DOS link full path, e.g., "\\??\\XyZabc-1A2B"
                RtlInitUnicodeString(&ValueName, L"DosDeviceName");
                ZwSetValueKey(ParametersKeyHandle, &ValueName, 0, REG_SZ, DosDeviceName.Buffer, DosDeviceName.Length + sizeof(WCHAR));

                // Persist the user-mode CreateFile path, e.g., "\\\\.\\XyZabc-1A2B"
                WCHAR UserDeviceNameBuffer[64] = {0};
                UNICODE_STRING UserDeviceName;
                RtlInitEmptyUnicodeString(&UserDeviceName, UserDeviceNameBuffer, sizeof(UserDeviceNameBuffer));
                RtlUnicodeStringPrintf(&UserDeviceName, L"\\\\.\\%ws-%04X", baseLeaf, suffix);

                RtlInitUnicodeString(&ValueName, L"UserDeviceName");
                ZwSetValueKey(ParametersKeyHandle, &ValueName, 0, REG_SZ, UserDeviceName.Buffer, UserDeviceName.Length + sizeof(WCHAR));

                ZwClose(ParametersKeyHandle);
            }
        }

        // Assign dispatch routines now that device and link are ready
        for (Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
            DriverObject->MajorFunction[Index] = DrvUnsupported;

        // We cannot use logging mechanism of HyperDbg as it's not initialized yet
        DbgPrint("Setting device major functions");

        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_READ]           = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE]          = DrvWrite;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchIoControl;

        DriverObject->DriverUnload = DrvUnload;

        // Successful setup
        break;
    }

    // Establish user-buffer access method and finalize
    if (DeviceObject)
    {
        DeviceObject->Flags |= DO_BUFFERED_IO;
        // We cannot use logging mechanism of HyperDbg as it's not initialized yet
        DbgPrint("Device and major functions are initialized");
    }

    ASSERT(NT_SUCCESS(Ntstatus));
    return Ntstatus;
}

/**
 * @brief Run in the case of driver unload to unregister the devices
 *
 * @param DriverObject
 * @return VOID
 */
VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    PHYPERKD_DEVICE_EXTENSION Ext = NULL;

    if (DriverObject && DriverObject->DeviceObject)
    {
        Ext = (PHYPERKD_DEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
        if (Ext && Ext->DosDeviceName.Buffer)
        {
            IoDeleteSymbolicLink(&Ext->DosDeviceName);
        }
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    //
    // Unloading VMM and Debugger
    //
    LoaderUninitializeLogTracer();
}

/**
 * @brief IRP_MJ_CREATE Function handler
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS
DrvCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Check for privilege
    //
    // Check for the correct security access.
    // The caller must have the SeDebugPrivilege.
    //

    LUID DebugPrivilege = {SE_DEBUG_PRIVILEGE, 0};

    if (!SeSinglePrivilegeCheck(DebugPrivilege, Irp->RequestorMode))
    {
        Irp->IoStatus.Status      = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_ACCESS_DENIED;
    }

    //
    // Check to allow just one handle to the driver
    // means that only one application can get the handle
    // and new application won't allowed to create a new
    // handle unless the IRP_MJ_CLOSE called.
    //
    if (g_HandleInUse)
    {
        //
        // A driver got the handle before
        //
        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    //
    // Initialize the vmm and the debugger
    //
    if (LoaderInitVmmAndDebugger())
    {
        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }
    else
    {
        //
        // There was a problem, so not loaded
        //
        Irp->IoStatus.Status      = STATUS_UNSUCCESSFUL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_UNSUCCESSFUL;
    }
}

/**
 * @brief IRP_MJ_READ Function handler
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS
DrvRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Not used
    //
    DbgPrint("This function is not used");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief IRP_MJ_WRITE Function handler
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS
DrvWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Not used
    //
    DbgPrint("This function is not used");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief IRP_MJ_CLOSE Function handler
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS
DrvClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // If the close is called means that all of the IOCTLs
    // are not in a pending state so we can safely allow
    // a new handle creation for future calls to the driver
    //
    g_HandleInUse = FALSE;

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief Unsupported message for all other IRP_MJ_* handlers
 *
 * @param DeviceObject
 * @param Irp
 * @return NTSTATUS
 */
NTSTATUS
DrvUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Not supported
    //
    DbgPrint("This function is not supported");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
