#include "pch.h"

//这里完成hook
NTSTATUS(*KdpTrapOrig)
(
    IN PKTRAP_FRAME      TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT          ContextRecord,
    IN KPROCESSOR_MODE   PreviousMode,
    IN BOOLEAN           SecondChanceException);

NTSTATUS
HookKdpTrap(
    IN PKTRAP_FRAME      TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT          ContextRecord,
    IN KPROCESSOR_MODE   PreviousMode,
    IN BOOLEAN           SecondChanceException)
{
    __try
    {
        PEPROCESS hp       = PsGetCurrentProcess();
        PCHAR     fileName = PsGetProcessImageFileName(hp);
        LogInfo("HookKdpTrap called for :  pid=%d, name=%s", GetCurrentProcessPID(), fileName);
        if (!_stricmp((char *)PsGetProcessImageFileName(hp), "TASLogin.exe"))
        {
            return STATUS_SUCCESS;
        }
    }
    __except (1)
    {
        LogWarning("_NtCreateFileHook error,pid = %d", GetCurrentProcessPID());
    }
    return KdpTrapOrig(TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChanceException);
}

VOID
NtHookKdpTrapInit()
{
    PVOID KdpTrapAddress = 0xfffff80047806fb8;

    if (!KdpTrapAddress)
    {
        LogError("Error in finding base address.");
        return FALSE;
    }

    if (EptHook3(KdpTrapAddress, HookKdpTrap, PsGetCurrentProcessId(), FALSE, FALSE, TRUE))
    {
        PLIST_ENTRY             TempList = &g_EptState->HookedPagesList;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry;
        while (&g_EptState->HookedPagesList != TempList->Flink)
        {
            TempList    = TempList->Flink;
            HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

            if (HookedEntry->VirtualAddress == KdpTrapAddress)
            {
                //
                // Means that we find the address
                //
                KdpTrapOrig = HookedEntry->Trampoline;
                break;
            }
        }
        LogDebugInfo("KdpTrapAddress = %llx,KdpTrapOrig = %llx\n", KdpTrapAddress, KdpTrapOrig);
    }
}