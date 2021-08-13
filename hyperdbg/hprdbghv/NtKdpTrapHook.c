#include "pch.h"

BOOLEAN
currentProcessOrChildProcessIsIn(PCHAR name,PCHAR *currentName,PCHAR *parentName) {
    PEPROCESS   peprocess = PsGetCurrentProcess();
    PEPROCESS   parentProcess;
    PCHAR       peIndex         = peprocess;
    PCHAR       fileName        = PsGetProcessImageFileName(peprocess);
    if (ARGUMENT_PRESENT(currentName))
    {
        *currentName = fileName;
    }
    UINT64      parentProcessId = *(UINT64 *)(peIndex + 0x3e8);
    PsLookupProcessByProcessId((HANDLE)parentProcessId, &parentProcess);
    PCHAR parentFileName = PsGetProcessImageFileName(parentProcess);
    if (ARGUMENT_PRESENT(parentName))
    {
        *parentName = parentFileName;
    }
    if (!_stricmp(fileName, name) || !_stricmp(parentFileName, name))
    {
        return TRUE;
    }
    return FALSE;
}

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
        PEPROCESS peprocess   = PsGetCurrentProcess();
        PEPROCESS parentProcess;
        PCHAR       peIndex       = peprocess;
        PCHAR       fileName  = PsGetProcessImageFileName(peprocess);
        UINT64      parentProcessId = *(UINT64 *)(peIndex + 0x3e8);
        PsLookupProcessByProcessId((HANDLE)parentProcessId, &parentProcess);
        PCHAR parentFileName = PsGetProcessImageFileName(parentProcess);
        if (!_stricmp(fileName, "wegame.exe") || !_stricmp(parentFileName, "wegame.exe"))
        {
            if (ExceptionRecord->ExceptionCode != (NTSTATUS)0xc0000005)
            {
                LogInfo("HookKdpTrap called for :  pid=%d,parentPid=%d name=%s,pName=%s, Rip = %llx, Code=%lx\n",
                        GetCurrentProcessPID(),
                        parentProcessId,
                        fileName,
                        parentFileName,
                        (UINT64)ContextRecord->Rip,
                        (UINT64)ExceptionRecord->ExceptionCode);
            }
           /* if (!_stricmp((char *)PsGetProcessImageFileName(peprocess), "TASLogin.exe"))
            {*/
                return EXCEPTION_CONTINUE_SEARCH;
            //} 
        }
        
    }
    __except (ExceptionFilter(GetExceptionInformation()))
    {
        LogWarning("HookKdpTrap error,pid = %d", GetCurrentProcessPID());
    }
    return KdpTrapOrig(TrapFrame, ExceptionFrame, ExceptionRecord, ContextRecord, PreviousMode, SecondChanceException);
}

VOID
NtHookKdpTrapInit()
{
    
    PVOID KdpTrapAddress = 0xfffff8025ee17fa8;

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