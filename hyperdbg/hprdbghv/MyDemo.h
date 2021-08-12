#pragma once
PDRIVER_OBJECT pDriverObject;

//VOID
//EptHookWriteAbsoluteJump3(PCHAR TargetBuffer, SIZE_T TargetAddress);
//
//BOOLEAN
//EptHookInstructionMemory3(PEPT_HOOKED_PAGE_DETAIL Hook, CR3_TYPE ProcessCr3, PVOID TargetFunction, PVOID TargetFunctionInSafeMemory, PVOID HookFunction);
//
BOOLEAN
EptHookPerformPageHook3(PVOID TargetAddress, PVOID HookFunction, CR3_TYPE ProcessCr3, BOOLEAN UnsetRead, BOOLEAN UnsetWrite, BOOLEAN UnsetExecute);

BOOLEAN
EptHook3(PVOID TargetAddress, PVOID HookFunction, UINT32 ProcessId, BOOLEAN SetHookForRead, BOOLEAN SetHookForWrite, BOOLEAN SetHookForExec);

UINT32
GetCurrentProcessPID();

INT32
ExceptionFilter(PEXCEPTION_POINTERS lpExceptionRecord);

/**
 * @brief Find entry from SSDT table of Nt fucntions and W32Table syscalls
 * 
 * @param ApiNumber The Syscall Number
 * @param GetFromWin32k Is this syscall from Win32K
 * @return PVOID Returns the address of the function from SSDT, otherwise returns NULL
 */
PVOID
SyscallHookGetFunctionAddress(INT32 ApiNumber, BOOLEAN GetFromWin32k);

PVOID
HookInitOnDerviceCreate();

VOID
NtCreateFileHookInit();
VOID
NtHookKdpTrapInit();
VOID
HideDriver();