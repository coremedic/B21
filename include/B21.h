#ifndef B21_B21_H
#define B21_B21_H

#include <windows.h>

#define LOGICAL ULONG

VOID B21Obf(DWORD dwSleepTime);
EXTERN_C VOID Trampoline(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer);

template<UINT64 N>
struct API_ARGS {
    UINT_PTR    pfnApi;
    UINT64      argCount = N;
    UINT_PTR    pArgs[N];
};

typedef struct _TP_CALLBACK_ENVIRON_V3 {
    ULONG Version;
    PTP_POOL Pool;
    PTP_CLEANUP_GROUP CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PVOID RaceDll;
    struct _ACTIVATION_CONTEXT *ActivationContext;
    PTP_SIMPLE_CALLBACK FinalizationCallback;
    union {
        struct {
            ULONG LongFunction : 1;
            ULONG Persistent : 1;
            ULONG Private : 30;
        } s;
        ULONG Flags;
    } u;
    TP_CALLBACK_PRIORITY CallbackPriority;
} TP_CALLBACK_ENVIRON_V3, *PTP_CALLBACK_ENVIRON_V3;

#define TP_CALLBACK_ENVIRON_V3_SIZE sizeof(TP_CALLBACK_ENVIRON_V3)
#define TP_CALLBACK_ENVIRON TP_CALLBACK_ENVIRON_V3
#define PTP_CALLBACK_ENVIRON PTP_CALLBACK_ENVIRON_V3


NTSYSAPI
NTSTATUS
NTAPI
TpAllocPool(
        _Out_ PTP_POOL *PoolReturn,
        _Reserved_ PVOID Reserved
);

NTSYSAPI
VOID
NTAPI
TpSetPoolMaxThreads(
        _Inout_ PTP_POOL Pool,
        _In_ ULONG MaxThreads
);

NTSYSAPI
NTSTATUS
NTAPI
TpSetPoolMinThreads(
        _Inout_ PTP_POOL Pool,
        _In_ ULONG MinThreads
);

NTSYSAPI
NTSTATUS
NTAPI
TpAllocCleanupGroup(
        _Out_ PTP_CLEANUP_GROUP *CleanupGroupReturn
);

NTSYSAPI
NTSTATUS
NTAPI
TpAllocTimer(
        _Out_ PTP_TIMER *Timer,
        _In_ PTP_TIMER_CALLBACK Callback,
        _Inout_opt_ PVOID Context,
        _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
);

NTSYSAPI
VOID
NTAPI
TpSetTimer(
        _Inout_ PTP_TIMER Timer,
        _In_opt_ PLARGE_INTEGER DueTime,
        _In_ ULONG Period,
        _In_opt_ ULONG WindowLength
);

NTSYSAPI
VOID
NTAPI
TpReleaseCleanupGroupMembers(
        _Inout_ PTP_CLEANUP_GROUP CleanupGroup,
        _In_ LOGICAL CancelPendingCallbacks,
        _Inout_opt_ PVOID CleanupParameter
);

#endif //B21_B21_H
