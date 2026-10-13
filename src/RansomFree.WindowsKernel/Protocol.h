#pragma once
// Private prototype protocol. Only administrators/SYSTEM may connect to the port.
#define SQ_PROTOCOL 4
#define SQ_PORT_NAME L"\\SeQuesterActorPrototype"
#define SQ_PATH_CHARS 768
#define SQ_SID_BYTES 68
#define SQ_QUEUE_LIMIT 2048
#define SQ_SET_ROOT 1
#define SQ_GET_EVENT 2
#define SQ_GET_HEALTH 3
#define SQ_ACK_EVENT 4
#define SQ_SET_PATHS 5
#define SQ_GET_THREAD_CONTEXT 40
#define SQ_GET_DEFERRED_TOKEN_CONTEXT 45
#define SQ_MAX_PATHS 128
#define SQ_F_THREAD_ABSENT 1
#define SQ_F_PROCESS_ABSENT 2
#define SQ_F_CONTEXT_IRQL 4
#define SQ_F_SUBJECT_ABSENT 8
#define SQ_F_IMAGE_ABSENT 16
#define SQ_F_TRUNCATED 32
#define SQ_F_IMPERSONATING 64
#define SQ_F_DRAINING 128
#define SQ_F_PAGING 256
#define SQ_F_FASTIO 512
#define SQ_F_REMOTE_FILESYSTEM 1024 // MUP client boundary; not proof of remote server execution.
#pragma pack(push,8)
typedef struct _SQ_TOKEN {
    ULONG Captured; // bit 0=user, 1=statistics, 2=session, 3=integrity, 4=elevation
    LONG UserStatus, StatisticsStatus, SessionStatus, IntegrityStatus, ElevationStatus;
    ULONG SidLength, SessionId, IntegrityRid, Elevated, TokenType, ImpersonationLevel;
    ULONGLONG TokenId, AuthenticationId, ModifiedId;
    UCHAR Sid[SQ_SID_BYTES];
} SQ_TOKEN;
typedef struct _SQ_MESSAGE {
    ULONG Version;
    ULONG Command;
    WCHAR Root[SQ_PATH_CHARS];
} SQ_MESSAGE;
typedef struct _SQ_EVENT {
    ULONG Version;
    ULONG Size;
    ULONGLONG Instance;
    ULONGLONG Sequence;
    LONGLONG ObservedUtc;
    LONGLONG CompletedUtc;
    LONGLONG ProcessCreatedUtc;
    ULONGLONG ProcessId;
    ULONGLONG ThreadId;
    ULONGLONG Information;
    ULONG Flags;
    ULONG Major;
    ULONG Minor;
    ULONG OperationClass;
    LONG Status;
    ULONG RequestorMode;
    ULONG SidLength;
    ULONG PrimarySidLength;
    UCHAR Sid[SQ_SID_BYTES];
    UCHAR PrimarySid[SQ_SID_BYTES];
    WCHAR Path[SQ_PATH_CHARS];
    WCHAR Image[SQ_PATH_CHARS];
    ULONG SubjectSource; // 0 unavailable, 1 CREATE access-state, 2 request-thread snapshot
    ULONG ThreadImpersonation; // 0 unavailable, 1 no token, 2 impersonating
    SQ_TOKEN CreateAuthorization;
    SQ_TOKEN ThreadEffective;
    SQ_TOKEN RequestorPrimary;
    ULONG DesiredAccess, CreateOptions, NameSource;
    LONG NameStatus;
    ULONG ThreadCopyOnOpen, ThreadEffectiveOnly, CaptureIrql, ThreadProcessId;
    LONGLONG MonotonicTicks, MonotonicFrequency;
} SQ_EVENT;
C_ASSERT(sizeof(SQ_TOKEN)==144);
C_ASSERT(sizeof(SQ_EVENT)==3800);
C_ASSERT(FIELD_OFFSET(SQ_EVENT,RequestorMode)==92);
// Additive queue-head extension. Legacy operation/ACK commands remain version 4.
// Only scalar snapshots are published; no token/process/thread pointers escape.
typedef struct _SQ_THREAD_CONTEXT {
    ULONG Version, Size;
    ULONGLONG Instance, Sequence;
    SQ_TOKEN ThreadOwnerPrimary;
    LONGLONG ThreadProcessCreatedUtc;
    ULONG CallbackDataFlags, RequestorMode;
} SQ_THREAD_CONTEXT;
C_ASSERT(sizeof(SQ_THREAD_CONTEXT)==184);
C_ASSERT(FIELD_OFFSET(SQ_THREAD_CONTEXT,ThreadOwnerPrimary)==24);
C_ASSERT(FIELD_OFFSET(SQ_THREAD_CONTEXT,ThreadProcessCreatedUtc)==168);
C_ASSERT(FIELD_OFFSET(SQ_THREAD_CONTEXT,CallbackDataFlags)==176);
C_ASSERT(FIELD_OFFSET(SQ_THREAD_CONTEXT,RequestorMode)==180);
typedef struct _SQ_CONTEXT_REPLY { SQ_EVENT Event; SQ_THREAD_CONTEXT Context; } SQ_CONTEXT_REPLY;
C_ASSERT(sizeof(SQ_CONTEXT_REPLY)==3984);
#ifdef SQ_DEFERRED_TOKEN_DIAGNOSTIC
// Separate from the immutable operation bytes. Reference time does not freeze
// mutable token fields; primary tokens and image are explicitly later queries.
typedef struct _SQ_DEFERRED_TOKEN_CONTEXT {
    ULONG Version, Size;
    ULONGLONG Instance, Sequence;
    LONGLONG ReferencedUtc, QueriedUtc;
    ULONG ReferenceIrql, Impersonation, CopyOnOpen, EffectiveOnly;
    LONG CollectionStatus;
    ULONG MetadataTiming; // 1 = later query of entry-referenced impersonation token
    ULONG EntryImpersonationLevel, Reserved;
    SQ_TOKEN ThreadEffective, ThreadOwnerPrimary, RequestorPrimary;
    LONGLONG ThreadProcessCreatedUtc;
    WCHAR Image[SQ_PATH_CHARS];
} SQ_DEFERRED_TOKEN_CONTEXT;
C_ASSERT(sizeof(SQ_DEFERRED_TOKEN_CONTEXT)==2048);
C_ASSERT(FIELD_OFFSET(SQ_DEFERRED_TOKEN_CONTEXT,ThreadEffective)==72);
C_ASSERT(FIELD_OFFSET(SQ_DEFERRED_TOKEN_CONTEXT,ThreadOwnerPrimary)==216);
C_ASSERT(FIELD_OFFSET(SQ_DEFERRED_TOKEN_CONTEXT,RequestorPrimary)==360);
C_ASSERT(FIELD_OFFSET(SQ_DEFERRED_TOKEN_CONTEXT,ThreadProcessCreatedUtc)==504);
C_ASSERT(FIELD_OFFSET(SQ_DEFERRED_TOKEN_CONTEXT,Image)==512);
#endif
typedef struct _SQ_HEALTH {
    ULONG Version;
    ULONG Size;
    ULONGLONG Instance;
    LONGLONG Sequence;
    LONGLONG Dropped;
    LONGLONG NameFailures;
    LONG Queued;
    ULONG RootConfigured;
} SQ_HEALTH;
#pragma pack(pop)
