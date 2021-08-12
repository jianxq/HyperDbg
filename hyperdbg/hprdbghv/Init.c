#include "pch.h"

PVOID
HookInitOnDerviceCreate()
{
    __try
    {
        //NtCreateFileHookInit();
        //NtHookKdpTrapInit();
        HideDriver();
    }
    __except (1)
    {
        LogError("HookInitOnDerviceCreate error");
    }
}