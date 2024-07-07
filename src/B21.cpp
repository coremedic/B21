#include <cstdio>
#include "B21.h"

VOID WINAPI InitializeThreadpoolEnvironment(PTP_CALLBACK_ENVIRON pcbe) {
    ZeroMemory(pcbe, TP_CALLBACK_ENVIRON_V3_SIZE);
    pcbe->Version = 3;
}

PVOID CopyTrampoline(PVOID (*trampoline)()) {
    PVOID pTrampolineAddr = NULL;

    pTrampolineAddr = VirtualAlloc(NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTrampolineAddr) {
        return NULL;
    }
    memcpy(pTrampolineAddr, (PVOID)trampoline, 84);

    return pTrampolineAddr;
}

VOID B21Obf(DWORD dwSleepTime) {
    VOID                (*pfnTrampoline)()  = NULL;
    PVOID               pImgBase            = NULL;
    DWORD               dwImgSize           = 0;
    DWORD               dwOldProtect        = 0;
    HANDLE              hEvent              = NULL;
    TP_CALLBACK_ENVIRON callbackEnviron     = {0};
    PTP_POOL            pThreadPool         = NULL;
    PTP_CLEANUP_GROUP   pCleanupGroup       = NULL;
    PTP_TIMER           pRwTimer            = NULL;
    PTP_TIMER           pRxTimer            = NULL;
    PTP_TIMER           pEventTimer         = NULL;
    LARGE_INTEGER       largeInt            = {0};
    API_ARGS<4>         virtualProtectRw;
    API_ARGS<4>         virtualProtectRx;
    API_ARGS<1>         setEvent;

    pImgBase    = GetModuleHandleA(NULL);
    dwImgSize   = ((PIMAGE_NT_HEADERS)(pImgBase + ((PIMAGE_DOS_HEADER)pImgBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    __typeof__(TpAllocPool)*                    TpAllocPool
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocPool");
    __typeof__(TpSetPoolMaxThreads)*            TpSetPoolMaxThreads
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetPoolMaxThreads");
    __typeof__(TpSetPoolMinThreads)*            TpSetPoolMinThreads
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetPoolMinThreads");
    __typeof__(TpAllocCleanupGroup)*            TpAllocCleanupGroup
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocCleanupGroup");
    __typeof__(TpAllocTimer)*                   TpAllocTimer
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocTimer");
    __typeof__(TpSetTimer)*                     TpSetTimer
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpSetTimer");
    __typeof__(TpReleaseCleanupGroupMembers)*   TpReleaseCleanupGroupMembers
    = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseCleanupGroupMembers");

    if (!TpSetPoolMaxThreads    ||
    !TpSetPoolMinThreads        ||
    !TpAllocCleanupGroup        ||
    !TpAllocTimer               ||
    !TpSetTimer                 ||
    !TpReleaseCleanupGroupMembers) {
#ifdef DEBUG
        printf("[!] Failed to resolve thread pool functions: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        goto EXIT;
    }

    pfnTrampoline = (VOID(*)())CopyTrampoline((PVOID(*)())Trampoline);
    if (!pfnTrampoline) {
#ifdef DEBUG
        printf("[!] Failed to copy trampoline: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        goto EXIT;
    }

#ifdef DEBUG
    printf("[i] Copied trampoline to RWX memory\n");
#endif

    InitializeThreadpoolEnvironment(&callbackEnviron);
    TpAllocPool(&pThreadPool, NULL);
    if (!pThreadPool) {
#ifdef DEBUG
        printf("[!] Failed to initialize thread pool environment: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        goto EXIT;
    }

#ifdef DEBUG
    printf("[i] Initialized thread pool\n");
#endif

    TpSetPoolMaxThreads(pThreadPool, 1);
    TpSetPoolMinThreads(pThreadPool, 1);
    TpAllocCleanupGroup(&pCleanupGroup);
    if (!pCleanupGroup) {
#ifdef DEBUG
        printf("[!] Failed to allocate cleanup group: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        goto EXIT;
    }

    hEvent = CreateEventA(0, 0, 0, 0);

    virtualProtectRw.pfnApi   = (UINT_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    virtualProtectRw.pArgs[0] = (UINT_PTR)pImgBase;
    virtualProtectRw.pArgs[1] = (UINT_PTR)dwImgSize;
    virtualProtectRw.pArgs[2] = (UINT_PTR)PAGE_READWRITE;
    virtualProtectRw.pArgs[3] = (UINT_PTR)&dwOldProtect;

    virtualProtectRx.pfnApi   = (UINT_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtect");
    virtualProtectRx.pArgs[0] = (UINT_PTR)pImgBase;
    virtualProtectRx.pArgs[1] = (UINT_PTR)dwImgSize;
    virtualProtectRx.pArgs[2] = (UINT_PTR)PAGE_EXECUTE_READWRITE;
    virtualProtectRx.pArgs[3] = (UINT_PTR)&dwOldProtect;

    setEvent.pfnApi     = (UINT_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetEvent");
    setEvent.pArgs[0]   = (UINT_PTR)hEvent;

    TpAllocTimer(&pRwTimer, (PTP_TIMER_CALLBACK)pfnTrampoline, &virtualProtectRw, &callbackEnviron);
    TpAllocTimer(&pRxTimer, (PTP_TIMER_CALLBACK)pfnTrampoline, &virtualProtectRx, &callbackEnviron);
    TpAllocTimer(&pEventTimer, (PTP_TIMER_CALLBACK)pfnTrampoline, &setEvent, &callbackEnviron);
    if (!pRwTimer || !pRxTimer || !pEventTimer) {
#ifdef DEBUG
        printf("[!] Failed to allocate thread pool timer: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        goto EXIT;
    }

#ifdef DEBUG
    printf("[i] Thread timers allocated\n");
#endif

#ifdef DEBUG
    printf("[i] Bed time!\n");
#endif

    largeInt.QuadPart = -(1LL * 10 * 1000 * 1000);
    TpSetTimer(pRwTimer, &largeInt, 0, 0);

    largeInt.QuadPart = -(LONGLONG)((dwSleepTime - 1) * 10000LL * 1000LL);
    TpSetTimer(pRxTimer, &largeInt, 0, 0);

    largeInt.QuadPart = -(LONGLONG)((dwSleepTime) * 10000LL * 1000LL);
    TpSetTimer(pEventTimer, &largeInt, 0, 0);

    WaitForSingleObject(hEvent, INFINITE);
    TpReleaseCleanupGroupMembers(pCleanupGroup, FALSE, NULL);

#ifdef DEBUG
    printf("[i] Sleep successful\n");
    printf("Press enter to exit\n");
    getchar();
#endif

    EXIT:
    if (pfnTrampoline) {
        VirtualFree((PVOID)pfnTrampoline, 0, MEM_RELEASE);
    }
    if (hEvent) {
        CloseHandle(hEvent);
    }
}