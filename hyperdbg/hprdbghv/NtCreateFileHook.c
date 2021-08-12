#include "pch.h"

NTSTATUS(*_NtCreateFileOrig)
(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength);

/**
 * @brief Hook function that hooks NtCreateFile
 * 
 * @param FileHandle 
 * @param DesiredAccess 
 * @param ObjectAttributes 
 * @param IoStatusBlock 
 * @param AllocationSize 
 * @param FileAttributes 
 * @param ShareAccess 
 * @param CreateDisposition 
 * @param CreateOptions 
 * @param EaBuffer 
 * @param EaLength 
 * @return NTSTATUS 
 */
NTSTATUS
_NtCreateFileHook(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    HANDLE         kFileHandle;
    NTSTATUS       ConvertStatus;
    UNICODE_STRING kObjectName;
    ANSI_STRING    FileNameA;

    kObjectName.Buffer = NULL;

    __try
    {
        ProbeForRead(FileHandle, sizeof(HANDLE), 1);
        ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
        ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
        ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);

        kFileHandle               = *FileHandle;
        kObjectName.Length        = ObjectAttributes->ObjectName->Length;
        kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
        kObjectName.Buffer        = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, 0xA);
        RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);

        ConvertStatus      = RtlUnicodeStringToAnsiString(&FileNameA, ObjectAttributes->ObjectName, TRUE);
        PEPROCESS hp       = PsGetCurrentProcess();
        PCHAR     fileName = PsGetProcessImageFileName(hp);
        LogInfo("NtCreateFile called for : %s, pid=%d, name=%s", FileNameA.Buffer, GetCurrentProcessPID(), fileName);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    if (kObjectName.Buffer)
    {
        ExFreePoolWithTag(kObjectName.Buffer, 0xA);
    }

    return _NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

/**
 * @brief NtCreateFileHookInitHook
 * 
 * @return VOID 
 */
VOID
NtCreateFileHookInit()
{
    //
    // Note that this syscall number is only valid for Windows 10 1909,
    // you have to find the syscall number of NtCreateFile based on
    // Your Windows version, please visit https://j00ru.vexillium.org/syscalls/nt/64/
    // for finding NtCreateFile's Syscall number for your Windows
    //

    INT32 ApiNumberOfNtCreateFile           = 0x0055;
    PVOID ApiLocationFromSSDTOfNtCreateFile = SyscallHookGetFunctionAddress(ApiNumberOfNtCreateFile, FALSE);

    if (!ApiLocationFromSSDTOfNtCreateFile)
    {
        LogError("Error in finding base address.");
        return FALSE;
    }

    if (EptHook3(ApiLocationFromSSDTOfNtCreateFile, _NtCreateFileHook, PsGetCurrentProcessId(), FALSE, FALSE, TRUE))
    {
        PLIST_ENTRY             TempList = &g_EptState->HookedPagesList;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry;
        while (&g_EptState->HookedPagesList != TempList->Flink)
        {
            TempList    = TempList->Flink;
            HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

            if (HookedEntry->VirtualAddress == ApiLocationFromSSDTOfNtCreateFile)
            {
                //
                // Means that we find the address
                //
                _NtCreateFileOrig = HookedEntry->Trampoline;
                break;
            }
        }
        LogDebugInfo("Hook appkied to address of API Number : 0x%x at %llx\n", ApiNumberOfNtCreateFile, ApiLocationFromSSDTOfNtCreateFile);
    }
}