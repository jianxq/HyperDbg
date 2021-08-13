#include "pch.h"


typedef struct _CURDIR
{
    UNICODE_STRING DosPath; //0x0
    VOID *         Handle;  //0x10
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;     //0x0
    USHORT Length;    //0x2
    ULONG  TimeStamp; //0x4
    STRING DosPath;   //0x8
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG                   MaximumLength;                    //0x0
    ULONG                   Length;                           //0x4
    ULONG                   Flags;                            //0x8
    ULONG                   DebugFlags;                       //0xc
    VOID *                  ConsoleHandle;                    //0x10
    ULONG                   ConsoleFlags;                     //0x18
    VOID *                  StandardInput;                    //0x20
    VOID *                  StandardOutput;                   //0x28
    VOID *                  StandardError;                    //0x30
    CURDIR                  CurrentDirectory;                 //0x38
    UNICODE_STRING          DllPath;                          //0x50
    UNICODE_STRING          ImagePathName;                    //0x60
    UNICODE_STRING          CommandLine;                      //0x70
    VOID *                  Environment;                      //0x80
    ULONG                   StartingX;                        //0x88
    ULONG                   StartingY;                        //0x8c
    ULONG                   CountX;                           //0x90
    ULONG                   CountY;                           //0x94
    ULONG                   CountCharsX;                      //0x98
    ULONG                   CountCharsY;                      //0x9c
    ULONG                   FillAttribute;                    //0xa0
    ULONG                   WindowFlags;                      //0xa4
    ULONG                   ShowWindowFlags;                  //0xa8
    UNICODE_STRING          WindowTitle;                      //0xb0
    UNICODE_STRING          DesktopInfo;                      //0xc0
    UNICODE_STRING          ShellInfo;                        //0xd0
    UNICODE_STRING          RuntimeData;                      //0xe0
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];            //0xf0
    ULONGLONG               EnvironmentSize;                  //0x3f0
    ULONGLONG               EnvironmentVersion;               //0x3f8
    VOID *                  PackageDependencyData;            //0x400
    ULONG                   ProcessGroupId;                   //0x408
    ULONG                   LoaderThreads;                    //0x40c
    UNICODE_STRING          RedirectionDllName;               //0x410
    UNICODE_STRING          HeapPartitionName;                //0x420
    ULONGLONG *             DefaultThreadpoolCpuSetMasks;     //0x430
    ULONG                   DefaultThreadpoolCpuSetMaskCount; //0x438
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION, *POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST
{
    ULONG     NumberOfAssignedProcesses;
    ULONG     NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} JOBOBJECT_BASIC_PROCESS_ID_LIST, *PJOBOBJECT_BASIC_PROCESS_ID_LIST;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG          TotalNumberOfObjects;
    ULONG          TotalNumberOfHandles;
    ULONG          Reserved[40];
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG                          NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR                         NumberOfHandles;
    ULONG_PTR                         Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
    BOOLEAN DebuggerAllowed;
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _WOW64_FLOATING_SAVE_AREA
{
    ULONG ControlWord;
    ULONG StatusWord;
    ULONG TagWord;
    ULONG ErrorOffset;
    ULONG ErrorSelector;
    ULONG DataOffset;
    ULONG DataSelector;
    UCHAR RegisterArea[80];
    ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT
{
    ULONG ContextFlags;

    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;

    WOW64_FLOATING_SAVE_AREA FloatSave;

    ULONG SegGs;
    ULONG SegFs;
    ULONG SegEs;
    ULONG SegDs;

    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;

    ULONG Ebp;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG Esp;
    ULONG SegSs;

    UCHAR ExtendedRegisters[512];

} WOW64_CONTEXT, *PWOW64_CONTEXT;

typedef struct _OBJECT_ALL_INFORMATION
{
    ULONG                   NumberOfObjectsTypes;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

typedef struct _SYSTEM_THREAD_INFO
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                     NextEntryOffset;
    ULONG                     NumberOfThreads;
    LARGE_INTEGER             WorkingSetPrivateSize;
    ULONG                     HardFaultCount;
    ULONG                     NumberOfThreadsHighWatermark;
    ULONGLONG                 CycleTime;
    LARGE_INTEGER             CreateTime;
    LARGE_INTEGER             UserTime;
    LARGE_INTEGER             KernelTime;
    UNICODE_STRING            ImageName;
    ULONG                     BasePriority;
    HANDLE                    ProcessId;
    HANDLE                    InheritedFromProcessId;
    ULONG                     HandleCount;
    ULONG                     SessionId;
    ULONG_PTR                 UniqueProcessKey;
    ULONG_PTR                 PeakVirtualSize;
    ULONG_PTR                 VirtualSize;
    ULONG                     PageFaultCount;
    ULONG_PTR                 PeakWorkingSetSize;
    ULONG_PTR                 WorkingSetSize;
    ULONG_PTR                 QuotaPeakPagedPoolUsage;
    ULONG_PTR                 QuotaPagedPoolUsage;
    ULONG_PTR                 QuotaPeakNonPagedPoolUsage;
    ULONG_PTR                 QuotaNonPagedPoolUsage;
    ULONG_PTR                 PagefileUsage;
    ULONG_PTR                 PeakPagefileUsage;
    ULONG_PTR                 PrivatePageCount;
    LARGE_INTEGER             ReadOperationCount;
    LARGE_INTEGER             WriteOperationCount;
    LARGE_INTEGER             OtherOperationCount;
    LARGE_INTEGER             ReadTransferCount;
    LARGE_INTEGER             WriteTransferCount;
    LARGE_INTEGER             OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;



typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32     InLoadOrderLinks;
    LIST_ENTRY32     InMemoryOrderLinks;
    LIST_ENTRY32     InInitializationOrderLinks;
    ULONG            DllBase;
    ULONG            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG            Flags;
    USHORT           LoadCount;
    USHORT           TlsIndex;
    LIST_ENTRY32     HashLinks;
    ULONG            TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY     InLoadOrderLinks;           //0x0
    struct _LIST_ENTRY     InMemoryOrderLinks;         //0x10
    struct _LIST_ENTRY     InInitializationOrderLinks; //0x20
    VOID *                 DllBase;                    //0x30
    VOID *                 EntryPoint;                 //0x38
    ULONG                  SizeOfImage;                //0x40
    struct _UNICODE_STRING FullDllName;                //0x48
    struct _UNICODE_STRING BaseDllName;                //0x58
    union
    {
        UCHAR FlagGroup[4]; //0x68
        ULONG Flags;        //0x68
        struct
        {
            ULONG PackagedBinary : 1;          //0x68
            ULONG MarkedForRemoval : 1;        //0x68
            ULONG ImageDll : 1;                //0x68
            ULONG LoadNotificationsSent : 1;   //0x68
            ULONG TelemetryEntryProcessed : 1; //0x68
            ULONG ProcessStaticImport : 1;     //0x68
            ULONG InLegacyLists : 1;           //0x68
            ULONG InIndexes : 1;               //0x68
            ULONG ShimDll : 1;                 //0x68
            ULONG InExceptionTable : 1;        //0x68
            ULONG ReservedFlags1 : 2;          //0x68
            ULONG LoadInProgress : 1;          //0x68
            ULONG LoadConfigProcessed : 1;     //0x68
            ULONG EntryProcessed : 1;          //0x68
            ULONG ProtectDelayLoad : 1;        //0x68
            ULONG ReservedFlags3 : 2;          //0x68
            ULONG DontCallForThreads : 1;      //0x68
            ULONG ProcessAttachCalled : 1;     //0x68
            ULONG ProcessAttachFailed : 1;     //0x68
            ULONG CorDeferredValidate : 1;     //0x68
            ULONG CorImage : 1;                //0x68
            ULONG DontRelocate : 1;            //0x68
            ULONG CorILOnly : 1;               //0x68
            ULONG ChpeImage : 1;               //0x68
            ULONG ReservedFlags5 : 2;          //0x68
            ULONG Redirected : 1;              //0x68
            ULONG ReservedFlags6 : 2;          //0x68
            ULONG CompatDatabaseProcessed : 1; //0x68
        };
    };
    USHORT                       ObsoleteLoadCount;           //0x6c
    USHORT                       TlsIndex;                    //0x6e
    struct _LIST_ENTRY           HashLinks;                   //0x70
    ULONG                        TimeDateStamp;               //0x80
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext; //0x88
    VOID *                       Lock;                        //0x90
    struct _LDR_DDAG_NODE *      DdagNode;                    //0x98
    struct _LIST_ENTRY           NodeModuleLink;              //0xa0
    struct _LDRP_LOAD_CONTEXT *  LoadContext;                 //0xb0
    VOID *                       ParentDllBase;               //0xb8
    VOID *                       SwitchBackContext;           //0xc0
    struct _RTL_BALANCED_NODE    BaseAddressIndexNode;        //0xc8
    struct _RTL_BALANCED_NODE    MappingInfoIndexNode;        //0xe0
    ULONGLONG                    OriginalBase;                //0xf8
    union _LARGE_INTEGER         LoadTime;                    //0x100
    ULONG                        BaseNameHashValue;           //0x108
    enum _LDR_DLL_LOAD_REASON    LoadReason;                  //0x10c
    ULONG                        ImplicitPathOptions;         //0x110
    ULONG                        ReferenceCount;              //0x114
    ULONG                        DependentLoadFlags;          //0x118
    UCHAR                        SigningLevel;                //0x11c
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE
{
    PVOID          Reserved1;
    PVOID          Reserved2;
    PVOID          ImageBaseAddress;
    ULONG          ImageSize;
    ULONG          Flags;
    unsigned short Id;
    unsigned short Rank;
    unsigned short Unknown;
    unsigned short NameOffset;
    unsigned char  Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;


struct _EX_FAST_REF
{
    union
    {
        VOID *    Object;     //0x0
        ULONGLONG RefCnt : 4; //0x0
        ULONGLONG Value;      //0x0
    };
};


#define BACKUP_RETURNLENGTH()           \
    ULONG TempReturnLength = 0;         \
    if (ARGUMENT_PRESENT(ReturnLength)) \
    TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH()          \
    if (ARGUMENT_PRESENT(ReturnLength)) \
    (*ReturnLength) = TempReturnLength

NTSTATUS(NTAPI * OriginalNtQuerySystemInformation)
(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS NTAPI
HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    __try
    {
        PEPROCESS hp             = PsGetCurrentProcess();
        PCHAR     fileName       = PsGetProcessImageFileName(hp);
        NTSTATUS  Status         = OriginalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        PEPROCESS CurrentProcess = IoGetCurrentProcess();

        if (ExGetPreviousMode() && NT_SUCCESS(Status) == TRUE)
        {
            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {
                PSYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

                BACKUP_RETURNLENGTH();
                DebuggerInfo->DebuggerEnabled    = 0;
                DebuggerInfo->DebuggerNotPresent = 1;
                RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemProcessInformation ||
                     SystemInformationClass == SystemSessionProcessInformation ||
                     SystemInformationClass == SystemExtendedProcessInformation ||
                     SystemInformationClass == SystemFullProcessInformation)
            {
                //PSYSTEM_PROCESS_INFO ProcessInfo = (PSYSTEM_PROCESS_INFO)SystemInformation;
                //if (SystemInformationClass == SystemSessionProcessInformation)
                //    ProcessInfo = (PSYSTEM_PROCESS_INFO)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

                //BACKUP_RETURNLENGTH();

                //FilterProcesses(ProcessInfo);

                //for (PSYSTEM_PROCESS_INFO Entry = ProcessInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR *)Entry + Entry->NextEntryOffset))
                //{
                //    if (Hider::IsHidden(PidToProcess(Entry->ProcessId), HIDE_NT_QUERY_SYSTEM_INFORMATION) == TRUE)
                //    {
                //        PEPROCESS ExplorerProcess = GetProcessByName(L"explorer.exe");
                //        if (ExplorerProcess != NULL)
                //            Entry->InheritedFromProcessId = PsGetProcessId(ExplorerProcess);

                //        Entry->OtherOperationCount.QuadPart = 1;
                //    }
                //}
                //RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemCodeIntegrityInformation)
            {
                BACKUP_RETURNLENGTH();
                ((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = 0x1; // CODEINTEGRITY_OPTION_ENABLED
                RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
            {
                BACKUP_RETURNLENGTH();
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
                RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemKernelDebuggerFlags)
            {
                BACKUP_RETURNLENGTH();
                *(UCHAR *)SystemInformation = NULL;
                RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemExtendedHandleInformation)
            {
                //PSYSTEM_HANDLE_INFORMATION_EX HandleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation;

                //BACKUP_RETURNLENGTH();
                //FilterHandlesEx(HandleInfoEx);
                //RESTORE_RETURNLENGTH();
            }

            else if (SystemInformationClass == SystemHandleInformation)
            {
                //PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)SystemInformation;

                //BACKUP_RETURNLENGTH();
                //FilterHandles(HandleInfo);
                //RESTORE_RETURNLENGTH();
            }
        }
        return Status;
    }
    __except (ExceptionFilter(GetExceptionInformation())) {
        LogWarning("Error in HookedNtQuerySystemInformation");
        return 0;
    }
}

VOID
HookedNtQuerySystemInformationInit()
{
    PVOID NtQuerySystemInformationAddress = 0Xfffff8057676bfa8;

    if (!NtQuerySystemInformationAddress)
    {
        LogError("Error in finding base address.");
        return FALSE;
    }

    if (EptHook3(NtQuerySystemInformationAddress, HookedNtQuerySystemInformation, PsGetCurrentProcessId(), FALSE, FALSE, TRUE))
    {
        PLIST_ENTRY             TempList = &g_EptState->HookedPagesList;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry;
        while (&g_EptState->HookedPagesList != TempList->Flink)
        {
            TempList    = TempList->Flink;
            HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

            if (HookedEntry->VirtualAddress == NtQuerySystemInformationAddress)
            {
                //
                // Means that we find the address
                //
                OriginalNtQuerySystemInformation = HookedEntry->Trampoline;
                break;
            }
        }
        LogDebugInfo("NtQuerySystemInformationAddress = %llx,OriginalNtQuerySystemInformation = %llx\n", NtQuerySystemInformationAddress, OriginalNtQuerySystemInformation);
    }
}