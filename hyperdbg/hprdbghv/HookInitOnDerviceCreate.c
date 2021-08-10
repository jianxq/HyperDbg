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
 * @brief Write an absolute x64 jump to an arbitrary address to a buffer
 * 
 * @param TargetBuffer 
 * @param TargetAddress 
 * @return VOID 
 */
VOID
EptHookWriteAbsoluteJump3(PCHAR TargetBuffer, SIZE_T TargetAddress)
{
    //
    // push Lower 4-byte TargetAddress
    //
    TargetBuffer[0] = 0x68;

    //
    // Lower 4-byte TargetAddress
    //
    *((PUINT32)&TargetBuffer[1]) = (UINT32)TargetAddress;

    //
    // mov [rsp+4],High 4-byte TargetAddress
    //
    TargetBuffer[5] = 0xC7;
    TargetBuffer[6] = 0x44;
    TargetBuffer[7] = 0x24;
    TargetBuffer[8] = 0x04;

    //
    // High 4-byte TargetAddress
    //
    *((PUINT32)&TargetBuffer[9]) = (UINT32)(TargetAddress >> 32);

    //
    // ret
    //
    TargetBuffer[13] = 0xC3;
}

/**
 * @brief Hook ins
 * 
 * @param Hook The details of hooked pages
 * @param ProcessCr3 The target Process CR3
 * @param TargetFunction Target function that needs to be hooked
 * @param TargetFunctionInSafeMemory Target content in the safe memory (used in Length Disassembler Engine)
 * @param HookFunction The function that will be called when hook triggered
 * @return BOOLEAN Returns true if the hook was successfull or returns false if it was not successfull
 */
BOOLEAN
EptHookInstructionMemory3(PEPT_HOOKED_PAGE_DETAIL Hook, CR3_TYPE ProcessCr3, PVOID TargetFunction, PVOID TargetFunctionInSafeMemory, PVOID HookFunction)
{
    PHIDDEN_HOOKS_DETOUR_DETAILS DetourHookDetails;
    SIZE_T                       SizeOfHookedInstructions;
    SIZE_T                       OffsetIntoPage;
    CR3_TYPE                     Cr3OfCurrentProcess;

    OffsetIntoPage = ADDRMASK_EPT_PML1_OFFSET((SIZE_T)TargetFunction);
    LogInfo("OffsetIntoPage: 0x%llx", OffsetIntoPage);

    if ((OffsetIntoPage + 19) > PAGE_SIZE - 1)
    {
        LogError("Function extends past a page boundary. We just don't have the technology to solve this.....");
        return FALSE;
    }

    //
    // Determine the number of instructions necessary to overwrite using Length Disassembler Engine
    //
    for (SizeOfHookedInstructions = 0;
         SizeOfHookedInstructions < 19;
         SizeOfHookedInstructions += ldisasm(((UINT64)TargetFunctionInSafeMemory + SizeOfHookedInstructions), TRUE))
    {
        //
        // Get the full size of instructions necessary to copy
        //
    }
    LogInfo("Number of bytes of instruction mem: %d", SizeOfHookedInstructions);

    //
    // Build a trampoline
    //

    //
    // Allocate some executable memory for the trampoline
    //
    Hook->Trampoline = PoolManagerRequestPool(EXEC_TRAMPOLINE, TRUE, MAX_EXEC_TRAMPOLINE_SIZE);

    if (!Hook->Trampoline)
    {
        LogError("Could not allocate trampoline function buffer.");
        return FALSE;
    }

    //
    // Copy the trampoline instructions in
    //

    // Switch to target process
    //
    Cr3OfCurrentProcess = SwitchOnAnotherProcessMemoryLayoutByCr3(ProcessCr3);

    //
    // The following line can't be used in user mode addresses
    // RtlCopyMemory(Hook->Trampoline, TargetFunction, SizeOfHookedInstructions);
    //
    MemoryMapperReadMemorySafe(TargetFunction, Hook->Trampoline, SizeOfHookedInstructions);

    //
    // Restore to original process
    //
    RestoreToPreviousProcess(Cr3OfCurrentProcess);

    //
    // Add the absolute jump back to the original function
    //
    EptHookWriteAbsoluteJump3(&Hook->Trampoline[SizeOfHookedInstructions], (SIZE_T)TargetFunction + SizeOfHookedInstructions);

    LogInfo("Trampoline: 0x%llx", Hook->Trampoline);
    LogInfo("HookFunction: 0x%llx", HookFunction);

    //
    // Let the hook function call the original function
    //
    // *OrigFunction = Hook->Trampoline;
    //

    //
    // Create the structure to return for the debugger, we do it here because it's the first
    // function that changes the original function and if our structure is no ready after this
    // fucntion then we probably see BSOD on other cores
    //
    DetourHookDetails                        = PoolManagerRequestPool(DETOUR_HOOK_DETAILS, TRUE, sizeof(HIDDEN_HOOKS_DETOUR_DETAILS));
    DetourHookDetails->HookedFunctionAddress = TargetFunction;
    DetourHookDetails->ReturnAddress         = Hook->Trampoline;

    //
    // Save the address of DetourHookDetails because we want to
    // deallocate it when the hook is finished
    //
    Hook->AddressOfEptHook2sDetourListEntry = DetourHookDetails;

    //
    // Insert it to the list of hooked pages
    //
    InsertHeadList(&g_EptHook2sDetourListHead, &(DetourHookDetails->OtherHooksList));

    //
    // Write the absolute jump to our shadow page memory to jump to our hook
    //
    EptHookWriteAbsoluteJump3(&Hook->FakePageContents[OffsetIntoPage], (SIZE_T)HookFunction);

    return TRUE;
}

BOOLEAN
EptHookPerformPageHook3(PVOID TargetAddress, PVOID HookFunction, CR3_TYPE ProcessCr3, BOOLEAN UnsetRead, BOOLEAN UnsetWrite, BOOLEAN UnsetExecute)
{
    EPT_PML1_ENTRY          ChangedEntry;
    INVEPT_DESCRIPTOR       Descriptor;
    SIZE_T                  PhysicalBaseAddress;
    PVOID                   VirtualTarget;
    PVOID                   TargetBuffer;
    UINT64                  TargetAddressInSafeMemory;
    UINT64                  PageOffset;
    PEPT_PML1_ENTRY         TargetPage;
    PEPT_HOOKED_PAGE_DETAIL HookedPage;
    ULONG                   LogicalCoreIndex;
    CR3_TYPE                Cr3OfCurrentProcess;
    PLIST_ENTRY             TempList    = 0;
    PEPT_HOOKED_PAGE_DETAIL HookedEntry = NULL;

    //
    // Check whether we are in VMX Root Mode or Not
    //
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

    if (g_GuestState[LogicalCoreIndex].IsOnVmxRootMode && !g_GuestState[LogicalCoreIndex].HasLaunched)
    {
        return FALSE;
    }

    //
    // Translate the page from a physical address to virtual so we can read its memory.
    // This function will return NULL if the physical address was not already mapped in
    // virtual memory.
    //
    VirtualTarget = PAGE_ALIGN(TargetAddress);

    //
    // Here we have to change the CR3, it is because we are in SYSTEM process
    // and if the target address is not mapped in SYSTEM address space (e.g
    // user mode address of another process) then the translation is invalid
    //

    //
    // Find cr3 of target core
    //
    PhysicalBaseAddress = (SIZE_T)VirtualAddressToPhysicalAddressByProcessCr3(VirtualTarget, ProcessCr3);

    if (!PhysicalBaseAddress)
    {
        LogError("Target address could not be mapped to physical memory");
        return FALSE;
    }

    //
    // try to see if we can find the address
    //
    TempList = &g_EptState->HookedPagesList;

    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList    = TempList->Flink;
        HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

        if (HookedEntry->PhysicalBaseAddress == PhysicalBaseAddress)
        {
            //
            // Means that we find the address and !epthook2 doesn't support
            // multiple breakpoints in on page
            //
            return FALSE;
        }
    }

    //
    // Set target buffer, request buffer from pool manager,
    // we also need to allocate new page to replace the current page ASAP
    //
    TargetBuffer = PoolManagerRequestPool(SPLIT_2MB_PAGING_TO_4KB_PAGE, TRUE, sizeof(VMM_EPT_DYNAMIC_SPLIT));

    if (!TargetBuffer)
    {
        LogError("There is no pre-allocated buffer available");
        return FALSE;
    }

    if (!EptSplitLargePage(g_EptState->EptPageTable, TargetBuffer, PhysicalBaseAddress, LogicalCoreIndex))
    {
        LogError("Could not split page for the address : 0x%llx", PhysicalBaseAddress);
        return FALSE;
    }

    //
    // Pointer to the page entry in the page table
    //
    TargetPage = EptGetPml1Entry(g_EptState->EptPageTable, PhysicalBaseAddress);

    //
    // Ensure the target is valid
    //
    if (!TargetPage)
    {
        LogError("Failed to get PML1 entry of the target address");
        return FALSE;
    }

    //
    // Save the original permissions of the page
    //
    ChangedEntry = *TargetPage;

    //
    // Execution is treated differently
    //
    if (UnsetRead)
        ChangedEntry.ReadAccess = 0;
    else
        ChangedEntry.ReadAccess = 1;

    if (UnsetWrite)
        ChangedEntry.WriteAccess = 0;
    else
        ChangedEntry.WriteAccess = 1;

    //
    // Save the detail of hooked page to keep track of it
    //
    HookedPage = PoolManagerRequestPool(TRACKING_HOOKED_PAGES, TRUE, sizeof(EPT_HOOKED_PAGE_DETAIL));

    if (!HookedPage)
    {
        LogError("There is no pre-allocated pool for saving hooked page details");
        return FALSE;
    }

    //
    // Save the virtual address
    //
    HookedPage->VirtualAddress = TargetAddress;

    //
    // Save the physical address
    //
    HookedPage->PhysicalBaseAddress = PhysicalBaseAddress;

    //
    // Fake page content physical address
    //
    HookedPage->PhysicalBaseAddressOfFakePageContents = (SIZE_T)VirtualAddressToPhysicalAddress(&HookedPage->FakePageContents[0]) / PAGE_SIZE;

    //
    // Save the entry address
    //
    HookedPage->EntryAddress = TargetPage;

    //
    // Save the orginal entry
    //
    HookedPage->OriginalEntry = *TargetPage;

    //
    // If it's Execution hook then we have to set extra fields
    //
    if (UnsetExecute)
    {
        //
        // Show that entry has hidden hooks for execution
        //
        HookedPage->IsExecutionHook = TRUE;

        //
        // In execution hook, we have to make sure to unset read, write because
        // an EPT violation should occur for these cases and we can swap the original page
        //
        ChangedEntry.ReadAccess    = 0;
        ChangedEntry.WriteAccess   = 0;
        ChangedEntry.ExecuteAccess = 1;

        //
        // Also set the current pfn to fake page
        //
        ChangedEntry.PageFrameNumber = HookedPage->PhysicalBaseAddressOfFakePageContents;

        //
        // Switch to target process
        //
        Cr3OfCurrentProcess = SwitchOnAnotherProcessMemoryLayoutByCr3(ProcessCr3);

        //
        // Copy the content to the fake page
        // The following line can't be used in user mode addresses
        // RtlCopyBytes(&HookedPage->FakePageContents, VirtualTarget, PAGE_SIZE);
        //
        MemoryMapperReadMemorySafe(VirtualTarget, &HookedPage->FakePageContents, PAGE_SIZE);

        //
        // Restore to original process
        //
        RestoreToPreviousProcess(Cr3OfCurrentProcess);

        //
        // Compute new offset of target offset into a safe bufferr
        // It will be used to compute the length of the detours
        // address because we might have a user mode code
        //
        TargetAddressInSafeMemory = &HookedPage->FakePageContents;
        TargetAddressInSafeMemory = PAGE_ALIGN(TargetAddressInSafeMemory);
        PageOffset                = PAGE_OFFSET(TargetAddress);
        TargetAddressInSafeMemory = TargetAddressInSafeMemory + PageOffset;

        //
        // Create Hook
        //
        if (!EptHookInstructionMemory3(HookedPage, ProcessCr3, TargetAddress, TargetAddressInSafeMemory, HookFunction))
        {
            LogError("Could not build the hook.");
            return FALSE;
        }
    }

    //
    // Save the modified entry
    //
    HookedPage->ChangedEntry = ChangedEntry;

    //
    // Add it to the list
    //
    InsertHeadList(&g_EptState->HookedPagesList, &(HookedPage->PageHookList));

    //
    // if not launched, there is no need to modify it on a safe environment
    //
    if (!g_GuestState[LogicalCoreIndex].HasLaunched)
    {
        //
        // Apply the hook to EPT
        //
        TargetPage->Flags = ChangedEntry.Flags;
    }
    else
    {
        //
        // Apply the hook to EPT
        //
        EptSetPML1AndInvalidateTLB(TargetPage, ChangedEntry, INVEPT_SINGLE_CONTEXT);
    }

    return TRUE;
}

/**
 * @brief This function allocates a buffer in VMX Non Root Mode and then invokes a VMCALL to set the hook
 * @details this command uses hidden detours, this NOT be called from vmx-root mode
 *
 *
 * @param TargetAddress The address of function or memory address to be hooked
 * @param HookFunction The function that will be called when hook triggered
 * @param ProcessId The process id to translate based on that process's cr3
 * @param SetHookForRead Hook READ Access
 * @param SetHookForWrite Hook WRITE Access
 * @param SetHookForExec Hook EXECUTE Access
 * @return BOOLEAN Returns true if the hook was successfull or false if there was an error
 */
BOOLEAN
EptHook3(PVOID TargetAddress, PVOID HookFunction, UINT32 ProcessId, BOOLEAN SetHookForRead, BOOLEAN SetHookForWrite, BOOLEAN SetHookForExec)
{
    UINT32 PageHookMask = 0;
    ULONG  LogicalCoreIndex;

    //
    // Check for the features to avoid EPT Violation problems
    //
    if (SetHookForExec && !g_ExecuteOnlySupport)
    {
        //
        // In the current design of hyperdbg we use execute-only pages to implement hidden hooks for exec page,
        // so your processor doesn't have this feature and you have to implment it in other ways :(
        //
        return FALSE;
    }

    if (SetHookForWrite && !SetHookForRead)
    {
        //
        // The hidden hook with Write Enable and Read Disabled will cause EPT violation!
        //
        return FALSE;
    }

    //
    // Check whether we are in VMX Root Mode or Not
    //
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

    if (SetHookForRead)
    {
        PageHookMask |= PAGE_ATTRIB_READ;
    }
    if (SetHookForWrite)
    {
        PageHookMask |= PAGE_ATTRIB_WRITE;
    }
    if (SetHookForExec)
    {
        PageHookMask |= PAGE_ATTRIB_EXEC;
    }

    if (PageHookMask == 0)
    {
        //
        // nothing to hook
        //
        return FALSE;
    }

    if (g_GuestState[LogicalCoreIndex].HasLaunched)
    {
        //
        // Move Attribute Mask to the upper 32 bits of the VMCALL Number
        //
        UINT64 VmcallNumber = ((UINT64)PageHookMask) << 32 | VMCALL_CHANGE_PAGE_ATTRIB1;

        if (AsmVmxVmcall(VmcallNumber, TargetAddress, HookFunction, GetCr3FromProcessId(ProcessId).Flags) == STATUS_SUCCESS)
        {
            LogInfo("Hook applied from VMX Root Mode");
            if (!g_GuestState[LogicalCoreIndex].IsOnVmxRootMode)
            {
                //
                // Now we have to notify all the core to invalidate their EPT
                //
                HvNotifyAllToInvalidateEpt();
            }
            else
            {
                LogError("Unable to notify all cores to invalidate their TLB caches as you called hook on vmx-root mode.");
            }

            return TRUE;
        }
    }
    else
    {
        if (EptHookPerformPageHook3(TargetAddress, HookFunction, GetCr3FromProcessId(ProcessId), SetHookForRead, SetHookForWrite, SetHookForExec) == TRUE)
        {
            LogInfo("[*] Hook applied (VM has not launched)");
            return TRUE;
        }
    }
    LogWarning("Hook not applied");

    return FALSE;
}

UINT32
GetCurrentProcessPID()
{
    return (UINT32)PsGetProcessId(PsGetCurrentProcess());
}

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

        ConvertStatus = RtlUnicodeStringToAnsiString(&FileNameA, ObjectAttributes->ObjectName, TRUE);
        if (3756 == GetCurrentProcessPID())
        {
            LogInfo("NtCreateFile called for : %s, pid=%d", FileNameA.Buffer, GetCurrentProcessPID());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LogWarning("_NtCreateFileHook error,pid = %d", GetCurrentProcessPID());
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

PVOID HookInitOnDerviceCreate() {
    NtCreateFileHookInit();
}