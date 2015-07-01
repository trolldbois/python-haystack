# 1 "Win7SP1X86._00003BA.32.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 148 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "Win7SP1X86._00003BA.32.h" 2






# 1 "/usr/include/clang/3.4/include/stdint.h" 1 3
# 62 "/usr/include/clang/3.4/include/stdint.h" 3
# 1 "/usr/include/stdint.h" 1 3 4
# 25 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/features.h" 1 3 4
# 352 "/usr/include/features.h" 3 4
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 353 "/usr/include/features.h" 2 3 4
# 374 "/usr/include/features.h" 3 4
# 1 "/usr/include/sys/cdefs.h" 1 3 4
# 385 "/usr/include/sys/cdefs.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 386 "/usr/include/sys/cdefs.h" 2 3 4
# 375 "/usr/include/features.h" 2 3 4
# 398 "/usr/include/features.h" 3 4
# 1 "/usr/include/gnu/stubs.h" 1 3 4






# 1 "/usr/include/gnu/stubs-32.h" 1 3 4
# 8 "/usr/include/gnu/stubs.h" 2 3 4
# 399 "/usr/include/features.h" 2 3 4
# 26 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/bits/wchar.h" 1 3 4
# 27 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 28 "/usr/include/stdint.h" 2 3 4








typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;



__extension__
typedef long long int int64_t;




typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;

typedef unsigned int uint32_t;





__extension__
typedef unsigned long long int uint64_t;






typedef signed char int_least8_t;
typedef short int int_least16_t;
typedef int int_least32_t;



__extension__
typedef long long int int_least64_t;



typedef unsigned char uint_least8_t;
typedef unsigned short int uint_least16_t;
typedef unsigned int uint_least32_t;



__extension__
typedef unsigned long long int uint_least64_t;






typedef signed char int_fast8_t;





typedef int int_fast16_t;
typedef int int_fast32_t;
__extension__
typedef long long int int_fast64_t;



typedef unsigned char uint_fast8_t;





typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;
__extension__
typedef unsigned long long int uint_fast64_t;
# 125 "/usr/include/stdint.h" 3 4
typedef int intptr_t;


typedef unsigned int uintptr_t;
# 137 "/usr/include/stdint.h" 3 4
__extension__
typedef long long int intmax_t;
__extension__
typedef unsigned long long int uintmax_t;
# 63 "/usr/include/clang/3.4/include/stdint.h" 2 3
# 8 "Win7SP1X86._00003BA.32.h" 2

typedef uint8_t UINT8;
typedef uint8_t UCHAR;
typedef uint8_t BOOL;

typedef int8_t CHAR;
typedef int8_t INT8;

typedef uint16_t WCHAR;
typedef uint16_t UINT16;
typedef uint16_t USHORT;
typedef int16_t SHORT;

typedef uint32_t UINT32;
typedef uint32_t ULONG;
typedef int32_t LONG;

typedef uint64_t UINT64;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;

typedef uint64_t PVOID64, PPVOID64;
typedef uint32_t PVOID32, PPVOID32;
typedef void VOID;

typedef double DOUBLE;
# 60 "Win7SP1X86._00003BA.32.h"
typedef UINT8 *PUINT8;
typedef UCHAR *PUCHAR;
typedef BOOL *PBOOL;

typedef CHAR *PCHAR;
typedef INT8 *PINT8;

typedef UINT16 *PUINT16;
typedef USHORT *PUSHORT;
typedef SHORT *PSHORT;

typedef UINT32 *PUINT32;
typedef ULONG *PULONG;
typedef LONG *PLONG;

typedef UINT64 *PUINT64;
typedef ULONGLONG *PULONGLONG;
typedef LONGLONG *PLONGLONG;

typedef VOID *PVOID, **PPVOID;






struct _HEAP;
typedef struct _HEAP HEAP;
typedef HEAP *PHEAP, **PPHEAP;

struct _HEAP_LOCAL_DATA;
typedef struct _HEAP_LOCAL_DATA HEAP_LOCAL_DATA;
typedef HEAP_LOCAL_DATA *PHEAP_LOCAL_DATA, **PPHEAP_LOCAL_DATA;

struct _HEAP_LOCAL_SEGMENT_INFO;
typedef struct _HEAP_LOCAL_SEGMENT_INFO HEAP_LOCAL_SEGMENT_INFO;
typedef HEAP_LOCAL_SEGMENT_INFO *PHEAP_LOCAL_SEGMENT_INFO, **PPHEAP_LOCAL_SEGMENT_INFO;

struct _HEAP_LOCK;
typedef struct _HEAP_LOCK HEAP_LOCK;
typedef HEAP_LOCK *PHEAP_LOCK, **PPHEAP_LOCK;

struct _HEAP_SUBSEGMENT;
typedef struct _HEAP_SUBSEGMENT HEAP_SUBSEGMENT;
typedef HEAP_SUBSEGMENT *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT;

struct _HEAP_USERDATA_HEADER;
typedef struct _HEAP_USERDATA_HEADER HEAP_USERDATA_HEADER;
typedef HEAP_USERDATA_HEADER *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER;

struct _LFH_HEAP;
typedef struct _LFH_HEAP LFH_HEAP;
typedef LFH_HEAP *PLFH_HEAP, **PPLFH_HEAP;

struct _RTL_CRITICAL_SECTION;
typedef struct _RTL_CRITICAL_SECTION RTL_CRITICAL_SECTION;
typedef RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION, **PPRTL_CRITICAL_SECTION;

struct _RTL_CRITICAL_SECTION_DEBUG;
typedef struct _RTL_CRITICAL_SECTION_DEBUG RTL_CRITICAL_SECTION_DEBUG;
typedef RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG, **PPRTL_CRITICAL_SECTION_DEBUG;



typedef struct _LIST_ENTRY {
 struct _LIST_ENTRY* Flink;
 struct _LIST_ENTRY* Blink;

} __attribute__((packed)) LIST_ENTRY, *PLIST_ENTRY, **PPLIST_ENTRY ;

typedef struct _SINGLE_LIST_ENTRY {
 struct _SINGLE_LIST_ENTRY* Next;

} __attribute__((packed)) SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY, **PPSINGLE_LIST_ENTRY ;

typedef struct _HEAP_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;
 USHORT TagIndex;
 USHORT CreatorBackTraceIndex;
 WCHAR TagName[0x18];

} __attribute__((packed)) HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY, **PPHEAP_TAG_ENTRY ;

typedef union _HEAP_BUCKET_COUNTERS {
 struct {
  volatile ULONG TotalBlocks;
  volatile ULONG SubSegmentCounts;
 };
 struct {
  volatile LONGLONG Aggregate64;
 };

} __attribute__((packed)) HEAP_BUCKET_COUNTERS, *PHEAP_BUCKET_COUNTERS, **PPHEAP_BUCKET_COUNTERS ;

typedef union _HEAP_BUCKET_RUN_INFO {
 struct {
  volatile ULONG Bucket;
  volatile ULONG RunLength;
 };
 struct {
  volatile LONGLONG Aggregate64;
 };

} __attribute__((packed)) HEAP_BUCKET_RUN_INFO, *PHEAP_BUCKET_RUN_INFO, **PPHEAP_BUCKET_RUN_INFO ;

typedef struct _INTERLOCK_SEQ {
union {
 struct {
  USHORT Depth;
  USHORT FreeEntryOffset;
 };
 struct {
  volatile ULONG OffsetAndDepth;
  volatile ULONG Sequence;
 };
 struct {
  volatile LONGLONG Exchg;
 };
};
} __attribute__((packed)) INTERLOCK_SEQ, *PINTERLOCK_SEQ, **PPINTERLOCK_SEQ ;

typedef struct _HEAP_BUCKET {
 USHORT BlockUnits;
 UCHAR SizeIndex;
 struct {
UCHAR UseAffinity : 1;
UCHAR DebugFlags : 2;
};

} __attribute__((packed)) HEAP_BUCKET, *PHEAP_BUCKET, **PPHEAP_BUCKET ;

typedef struct _HEAP_COUNTERS {
 ULONG TotalMemoryReserved;
 ULONG TotalMemoryCommitted;
 ULONG TotalMemoryLargeUCR;
 ULONG TotalSizeInVirtualBlocks;
 ULONG TotalSegments;
 ULONG TotalUCRs;
 ULONG CommittOps;
 ULONG DeCommitOps;
 ULONG LockAcquires;
 ULONG LockCollisions;
 ULONG CommitRate;
 ULONG DecommittRate;
 ULONG CommitFailures;
 ULONG InBlockCommitFailures;
 ULONG CompactHeapCalls;
 ULONG CompactedUCRs;
 ULONG AllocAndFreeOps;
 ULONG InBlockDeccommits;
 ULONG InBlockDeccomitSize;
 ULONG HighWatermarkSize;
 ULONG LastPolledSize;

} __attribute__((packed)) HEAP_COUNTERS, *PHEAP_COUNTERS, **PPHEAP_COUNTERS ;

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;

} __attribute__((packed)) HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY, **PPHEAP_PSEUDO_TAG_ENTRY ;

typedef struct _HEAP_ENTRY {
union {
 struct {
  USHORT Size;
  UCHAR Flags;
  UCHAR SmallTagIndex;
 };
 struct {
  PVOID SubSegmentCode;
  USHORT PreviousSize;
  union {
   UCHAR SegmentOffset;
   UCHAR LFHFlags;
  };
  UCHAR UnusedBytes;
 };
 struct {
  USHORT FunctionIndex;
  USHORT ContextValue;
 };
 struct {
  ULONG InterceptorValue;
  USHORT UnusedBytesLength;
  UCHAR EntryOffset;
  UCHAR ExtendedBlockSignature;
 };
 struct {
  ULONG Code1;
  USHORT Code2;
  UCHAR Code3;
  UCHAR Code4;
 };
 struct {
  ULONGLONG AgregateCode;
 };
};
} __attribute__((packed)) HEAP_ENTRY, *PHEAP_ENTRY, **PPHEAP_ENTRY ;

typedef struct _HEAP_TUNING_PARAMETERS {
 ULONG CommittThresholdShift;
 ULONG MaxPreCommittThreshold;

} __attribute__((packed)) HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS, **PPHEAP_TUNING_PARAMETERS ;

typedef struct _LFH_BLOCK_ZONE {
 LIST_ENTRY ListEntry;
 PVOID FreePointer;
 PVOID Limit;

} __attribute__((packed)) LFH_BLOCK_ZONE, *PLFH_BLOCK_ZONE, **PPLFH_BLOCK_ZONE ;

typedef union _SLIST_HEADER {
 ULONGLONG Alignment;
 struct {
  SINGLE_LIST_ENTRY Next;
  USHORT Depth;
  USHORT Sequence;
 };

} __attribute__((packed)) SLIST_HEADER, *PSLIST_HEADER, **PPSLIST_HEADER ;

typedef struct _USER_MEMORY_CACHE_ENTRY {
 SLIST_HEADER UserBlocks;
 ULONG AvailableBlocks;
 UINT8 gap_in_pdb_ofs_C[0x4];

} __attribute__((packed)) USER_MEMORY_CACHE_ENTRY, *PUSER_MEMORY_CACHE_ENTRY, **PPUSER_MEMORY_CACHE_ENTRY ;

typedef struct _RTL_CRITICAL_SECTION {
 PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
 LONG LockCount;
 LONG RecursionCount;
 PVOID OwningThread;
 PVOID LockSemaphore;
 ULONG SpinCount;

} __attribute__((packed)) RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION, **PPRTL_CRITICAL_SECTION ;

typedef struct _HEAP_LOCAL_SEGMENT_INFO {
 PHEAP_SUBSEGMENT Hint;
 PHEAP_SUBSEGMENT ActiveSubsegment;
 PHEAP_SUBSEGMENT CachedItems[0x10];
 SLIST_HEADER SListHeader;
 HEAP_BUCKET_COUNTERS Counters;
 volatile PHEAP_LOCAL_DATA LocalData;
 ULONG LastOpSequence;
 volatile USHORT BucketIndex;
 USHORT LastUsed;
 UINT8 gap_in_pdb_ofs_64[0x4];

} __attribute__((packed)) HEAP_LOCAL_SEGMENT_INFO, *PHEAP_LOCAL_SEGMENT_INFO, **PPHEAP_LOCAL_SEGMENT_INFO ;

typedef struct _HEAP_SUBSEGMENT {
 PHEAP_LOCAL_SEGMENT_INFO LocalInfo;
 volatile PHEAP_USERDATA_HEADER UserBlocks;
 INTERLOCK_SEQ AggregateExchg;
 union {
  struct {
   USHORT BlockSize;
   USHORT Flags;
   USHORT BlockCount;
   UCHAR SizeIndex;
   UCHAR AffinityIndex;
  };
  ULONG Alignment[0x2];
 };
 SINGLE_LIST_ENTRY SFreeListEntry;
 volatile ULONG Lock;

} __attribute__((packed)) HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT ;

typedef struct _HEAP_LOCAL_DATA {
 SLIST_HEADER DeletedSubSegments;
 PLFH_BLOCK_ZONE CrtZone;
 volatile PLFH_HEAP LowFragHeap;
 ULONG Sequence;
 UINT8 gap_in_pdb_ofs_14[0x4];
 HEAP_LOCAL_SEGMENT_INFO SegmentInfo[0x80];

} __attribute__((packed)) HEAP_LOCAL_DATA, *PHEAP_LOCAL_DATA, **PPHEAP_LOCAL_DATA ;

typedef struct _LFH_HEAP {
 RTL_CRITICAL_SECTION Lock;
 LIST_ENTRY SubSegmentZones;
 ULONG ZoneBlockSize;
 PVOID Heap;
 ULONG SegmentChange;
 ULONG SegmentCreate;
 ULONG SegmentInsertInFree;
 ULONG SegmentDelete;
 ULONG CacheAllocs;
 ULONG CacheFrees;
 ULONG SizeInCache;
 UINT8 gap_in_pdb_ofs_44[0x4];
 HEAP_BUCKET_RUN_INFO RunInfo;
 USER_MEMORY_CACHE_ENTRY UserBlockCache[0xc];
 HEAP_BUCKET Buckets[0x80];
 HEAP_LOCAL_DATA LocalData[0x1];

} __attribute__((packed)) LFH_HEAP, *PLFH_HEAP, **PPLFH_HEAP ;

typedef struct _HEAP_LOCK {
 union {
 RTL_CRITICAL_SECTION CriticalSection;
} Lock;

} __attribute__((packed)) HEAP_LOCK, *PHEAP_LOCK, **PPHEAP_LOCK ;

typedef struct _HEAP_USERDATA_HEADER {
union {
 SINGLE_LIST_ENTRY SFreeListEntry;
 struct {
  PHEAP_SUBSEGMENT SubSegment;
  PVOID Reserved;
  ULONG SizeIndex;
  ULONG Signature;
 };
};
} __attribute__((packed)) HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER ;

typedef struct _RTL_CRITICAL_SECTION_DEBUG {
 USHORT Type;
 USHORT CreatorBackTraceIndex;
 PRTL_CRITICAL_SECTION CriticalSection;
 LIST_ENTRY ProcessLocksList;
 ULONG EntryCount;
 ULONG ContentionCount;
 ULONG Flags;
 USHORT CreatorBackTraceIndexHigh;
 USHORT SpareUSHORT;

} __attribute__((packed)) RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, **PPRTL_CRITICAL_SECTION_DEBUG ;

typedef struct _HEAP {
 HEAP_ENTRY Entry;
 ULONG SegmentSignature;
 ULONG SegmentFlags;
 LIST_ENTRY SegmentListEntry;
 struct _HEAP* Heap;
 PVOID BaseAddress;
 ULONG NumberOfPages;
 PHEAP_ENTRY FirstEntry;
 PHEAP_ENTRY LastValidEntry;
 ULONG NumberOfUnCommittedPages;
 ULONG NumberOfUnCommittedRanges;
 USHORT SegmentAllocatorBackTraceIndex;
 USHORT Reserved;
 LIST_ENTRY UCRSegmentList;
 ULONG Flags;
 ULONG ForceFlags;
 ULONG CompatibilityFlags;
 ULONG EncodeFlagMask;
 HEAP_ENTRY Encoding;
 ULONG PointerKey;
 ULONG Interceptor;
 ULONG VirtualMemoryThreshold;
 ULONG Signature;
 ULONG SegmentReserve;
 ULONG SegmentCommit;
 ULONG DeCommitFreeBlockThreshold;
 ULONG DeCommitTotalFreeThreshold;
 ULONG TotalFreeSize;
 ULONG MaximumAllocationSize;
 USHORT ProcessHeapsListIndex;
 USHORT HeaderValidateLength;
 PVOID HeaderValidateCopy;
 USHORT NextAvailableTagIndex;
 USHORT MaximumTagIndex;
 PHEAP_TAG_ENTRY TagEntries;
 LIST_ENTRY UCRList;
 ULONG AlignRound;
 ULONG AlignMask;
 LIST_ENTRY VirtualAllocdBlocks;
 LIST_ENTRY SegmentList;
 USHORT AllocatorBackTraceIndex;
 UINT8 gap_in_pdb_ofs_B2[0x2];
 ULONG NonDedicatedListLength;
 PVOID BlocksIndex;
 PVOID UCRIndex;
 PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
 LIST_ENTRY FreeLists;
 PHEAP_LOCK LockVariable;
 LONG (*CommitRoutine)(PVOID, PPVOID, PULONG);
 PVOID FrontEndHeap;
 USHORT FrontHeapLockCount;
 UCHAR FrontEndHeapType;
 UINT8 gap_in_pdb_ofs_DB[0x1];
 HEAP_COUNTERS Counters;
 HEAP_TUNING_PARAMETERS TuningParameters;

} __attribute__((packed)) HEAP, *PHEAP, **PPHEAP ;
# 1 "Win7SP1X86._000160E.32.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 148 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "Win7SP1X86._000160E.32.h" 2






# 1 "/usr/include/clang/3.4/include/stdint.h" 1 3
# 62 "/usr/include/clang/3.4/include/stdint.h" 3
# 1 "/usr/include/stdint.h" 1 3 4
# 25 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/features.h" 1 3 4
# 352 "/usr/include/features.h" 3 4
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 353 "/usr/include/features.h" 2 3 4
# 374 "/usr/include/features.h" 3 4
# 1 "/usr/include/sys/cdefs.h" 1 3 4
# 385 "/usr/include/sys/cdefs.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 386 "/usr/include/sys/cdefs.h" 2 3 4
# 375 "/usr/include/features.h" 2 3 4
# 398 "/usr/include/features.h" 3 4
# 1 "/usr/include/gnu/stubs.h" 1 3 4






# 1 "/usr/include/gnu/stubs-32.h" 1 3 4
# 8 "/usr/include/gnu/stubs.h" 2 3 4
# 399 "/usr/include/features.h" 2 3 4
# 26 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/bits/wchar.h" 1 3 4
# 27 "/usr/include/stdint.h" 2 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 28 "/usr/include/stdint.h" 2 3 4








typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;



__extension__
typedef long long int int64_t;




typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;

typedef unsigned int uint32_t;





__extension__
typedef unsigned long long int uint64_t;






typedef signed char int_least8_t;
typedef short int int_least16_t;
typedef int int_least32_t;



__extension__
typedef long long int int_least64_t;



typedef unsigned char uint_least8_t;
typedef unsigned short int uint_least16_t;
typedef unsigned int uint_least32_t;



__extension__
typedef unsigned long long int uint_least64_t;






typedef signed char int_fast8_t;





typedef int int_fast16_t;
typedef int int_fast32_t;
__extension__
typedef long long int int_fast64_t;



typedef unsigned char uint_fast8_t;





typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;
__extension__
typedef unsigned long long int uint_fast64_t;
# 125 "/usr/include/stdint.h" 3 4
typedef int intptr_t;


typedef unsigned int uintptr_t;
# 137 "/usr/include/stdint.h" 3 4
__extension__
typedef long long int intmax_t;
__extension__
typedef unsigned long long int uintmax_t;
# 63 "/usr/include/clang/3.4/include/stdint.h" 2 3
# 8 "Win7SP1X86._000160E.32.h" 2

typedef uint8_t UINT8;
typedef uint8_t UCHAR;
typedef uint8_t BOOL;

typedef int8_t CHAR;
typedef int8_t INT8;

typedef uint16_t WCHAR;
typedef uint16_t UINT16;
typedef uint16_t USHORT;
typedef int16_t SHORT;

typedef uint32_t UINT32;
typedef uint32_t ULONG;
typedef int32_t LONG;

typedef uint64_t UINT64;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;

typedef uint64_t PVOID64, PPVOID64;
typedef uint32_t PVOID32, PPVOID32;
typedef void VOID;

typedef double DOUBLE;
# 60 "Win7SP1X86._000160E.32.h"
typedef UINT8 *PUINT8;
typedef UCHAR *PUCHAR;
typedef BOOL *PBOOL;

typedef CHAR *PCHAR;
typedef INT8 *PINT8;

typedef UINT16 *PUINT16;
typedef USHORT *PUSHORT;
typedef SHORT *PSHORT;

typedef UINT32 *PUINT32;
typedef ULONG *PULONG;
typedef LONG *PLONG;

typedef UINT64 *PUINT64;
typedef ULONGLONG *PULONGLONG;
typedef LONGLONG *PLONGLONG;

typedef VOID *PVOID, **PPVOID;
# 88 "Win7SP1X86._000160E.32.h"
struct _HEAP;
typedef struct _HEAP HEAP;
typedef HEAP *PHEAP, **PPHEAP;

struct _HEAP_LOCK;
typedef struct _HEAP_LOCK HEAP_LOCK;
typedef HEAP_LOCK *PHEAP_LOCK, **PPHEAP_LOCK;

struct _HEAP_SEGMENT;
typedef struct _HEAP_SEGMENT HEAP_SEGMENT;
typedef HEAP_SEGMENT *PHEAP_SEGMENT, **PPHEAP_SEGMENT;

struct _HEAP_SUBSEGMENT;
typedef struct _HEAP_SUBSEGMENT HEAP_SUBSEGMENT;
typedef HEAP_SUBSEGMENT *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT;

struct _HEAP_USERDATA_HEADER;
typedef struct _HEAP_USERDATA_HEADER HEAP_USERDATA_HEADER;
typedef HEAP_USERDATA_HEADER *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER;

struct _RTL_CRITICAL_SECTION;
typedef struct _RTL_CRITICAL_SECTION RTL_CRITICAL_SECTION;
typedef RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION, **PPRTL_CRITICAL_SECTION;

struct _RTL_CRITICAL_SECTION_DEBUG;
typedef struct _RTL_CRITICAL_SECTION_DEBUG RTL_CRITICAL_SECTION_DEBUG;
typedef RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG, **PPRTL_CRITICAL_SECTION_DEBUG;



typedef struct _LIST_ENTRY {
 struct _LIST_ENTRY* Flink;
 struct _LIST_ENTRY* Blink;

} __attribute__((packed)) LIST_ENTRY, *PLIST_ENTRY, **PPLIST_ENTRY ;

typedef struct _SINGLE_LIST_ENTRY {
 struct _SINGLE_LIST_ENTRY* Next;

} __attribute__((packed)) SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY, **PPSINGLE_LIST_ENTRY ;

typedef struct _HEAP_ENTRY {
union {
 struct {
  USHORT Size;
  UCHAR Flags;
  UCHAR SmallTagIndex;
 };
 struct {
  PVOID SubSegmentCode;
  USHORT PreviousSize;
  union {
   UCHAR SegmentOffset;
   UCHAR LFHFlags;
  };
  UCHAR UnusedBytes;
 };
 struct {
  USHORT FunctionIndex;
  USHORT ContextValue;
 };
 struct {
  ULONG InterceptorValue;
  USHORT UnusedBytesLength;
  UCHAR EntryOffset;
  UCHAR ExtendedBlockSignature;
 };
 struct {
  ULONG Code1;
  USHORT Code2;
  UCHAR Code3;
  UCHAR Code4;
 };
 struct {
  ULONGLONG AgregateCode;
 };
};
} __attribute__((packed)) HEAP_ENTRY, *PHEAP_ENTRY, **PPHEAP_ENTRY ;

typedef struct _HEAP_COUNTERS {
 ULONG TotalMemoryReserved;
 ULONG TotalMemoryCommitted;
 ULONG TotalMemoryLargeUCR;
 ULONG TotalSizeInVirtualBlocks;
 ULONG TotalSegments;
 ULONG TotalUCRs;
 ULONG CommittOps;
 ULONG DeCommitOps;
 ULONG LockAcquires;
 ULONG LockCollisions;
 ULONG CommitRate;
 ULONG DecommittRate;
 ULONG CommitFailures;
 ULONG InBlockCommitFailures;
 ULONG CompactHeapCalls;
 ULONG CompactedUCRs;
 ULONG AllocAndFreeOps;
 ULONG InBlockDeccommits;
 ULONG InBlockDeccomitSize;
 ULONG HighWatermarkSize;
 ULONG LastPolledSize;

} __attribute__((packed)) HEAP_COUNTERS, *PHEAP_COUNTERS, **PPHEAP_COUNTERS ;

typedef struct _HEAP_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;
 USHORT TagIndex;
 USHORT CreatorBackTraceIndex;
 WCHAR TagName[0x18];

} __attribute__((packed)) HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY, **PPHEAP_TAG_ENTRY ;

typedef struct _INTERLOCK_SEQ {
union {
 struct {
  USHORT Depth;
  USHORT FreeEntryOffset;
 };
 struct {
  volatile ULONG OffsetAndDepth;
  volatile ULONG Sequence;
 };
 struct {
  volatile LONGLONG Exchg;
 };
};
} __attribute__((packed)) INTERLOCK_SEQ, *PINTERLOCK_SEQ, **PPINTERLOCK_SEQ ;

typedef struct _HEAP_ENTRY_EXTRA {
union {
 struct {
  USHORT AllocatorBackTraceIndex;
  USHORT TagIndex;
  ULONG Settable;
 };
 struct {
  ULONGLONG ZeroInit;
 };
};
} __attribute__((packed)) HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA, **PPHEAP_ENTRY_EXTRA ;

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;

} __attribute__((packed)) HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY, **PPHEAP_PSEUDO_TAG_ENTRY ;

typedef struct _HEAP_TUNING_PARAMETERS {
 ULONG CommittThresholdShift;
 ULONG MaxPreCommittThreshold;

} __attribute__((packed)) HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS, **PPHEAP_TUNING_PARAMETERS ;

typedef struct _HEAP_LIST_LOOKUP {
 struct _HEAP_LIST_LOOKUP* ExtendedLookup;
 ULONG ArraySize;
 ULONG ExtraItem;
 ULONG ItemCount;
 ULONG OutOfRangeItems;
 ULONG BaseIndex;
 PLIST_ENTRY ListHead;
 PULONG ListsInUseUlong;
 PPLIST_ENTRY ListHints;

} __attribute__((packed)) HEAP_LIST_LOOKUP, *PHEAP_LIST_LOOKUP, **PPHEAP_LIST_LOOKUP ;

typedef union _SLIST_HEADER {
 ULONGLONG Alignment;
 struct {
  SINGLE_LIST_ENTRY Next;
  USHORT Depth;
  USHORT Sequence;
 };

} __attribute__((packed)) SLIST_HEADER, *PSLIST_HEADER, **PPSLIST_HEADER ;

typedef struct _HEAP_UCR_DESCRIPTOR {
 LIST_ENTRY ListEntry;
 LIST_ENTRY SegmentEntry;
 PVOID Address;
 ULONG Size;

} __attribute__((packed)) HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR, **PPHEAP_UCR_DESCRIPTOR ;

typedef struct _HEAP_LOOKASIDE {
 SLIST_HEADER ListHead;
 USHORT Depth;
 USHORT MaximumDepth;
 ULONG TotalAllocates;
 ULONG AllocateMisses;
 ULONG TotalFrees;
 ULONG FreeMisses;
 ULONG LastTotalAllocates;
 ULONG LastAllocateMisses;
 ULONG Counters[0x2];
 UINT8 gap_in_pdb_ofs_2C[0x4];

} __attribute__((packed)) HEAP_LOOKASIDE, *PHEAP_LOOKASIDE, **PPHEAP_LOOKASIDE ;

typedef struct _HEAP_FREE_ENTRY {
union {
 struct {
  USHORT Size;
  UCHAR Flags;
  UCHAR SmallTagIndex;
 };
 struct {
  PVOID SubSegmentCode;
  USHORT PreviousSize;
  union {
   UCHAR SegmentOffset;
   UCHAR LFHFlags;
  };
  UCHAR UnusedBytes;
 };
 struct {
  USHORT FunctionIndex;
  USHORT ContextValue;
 };
 struct {
  ULONG InterceptorValue;
  USHORT UnusedBytesLength;
  UCHAR EntryOffset;
  UCHAR ExtendedBlockSignature;
 };
 struct {
  ULONG Code1;
  USHORT Code2;
  UCHAR Code3;
  UCHAR Code4;
 };
 struct {
  ULONGLONG AgregateCode;
  LIST_ENTRY FreeList;
 };
};
} __attribute__((packed)) HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY, **PPHEAP_FREE_ENTRY ;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY {
 LIST_ENTRY Entry;
 HEAP_ENTRY_EXTRA ExtraStuff;
 ULONG CommitSize;
 ULONG ReserveSize;
 HEAP_ENTRY BusyBlock;

} __attribute__((packed)) HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY, **PPHEAP_VIRTUAL_ALLOC_ENTRY ;

typedef struct _RTL_CRITICAL_SECTION {
 PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
 LONG LockCount;
 LONG RecursionCount;
 PVOID OwningThread;
 PVOID LockSemaphore;
 ULONG SpinCount;

} __attribute__((packed)) RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION, **PPRTL_CRITICAL_SECTION ;

typedef struct _HEAP {
 HEAP_ENTRY Entry;
 ULONG SegmentSignature;
 ULONG SegmentFlags;
 LIST_ENTRY SegmentListEntry;
 struct _HEAP* Heap;
 PVOID BaseAddress;
 ULONG NumberOfPages;
 PHEAP_ENTRY FirstEntry;
 PHEAP_ENTRY LastValidEntry;
 ULONG NumberOfUnCommittedPages;
 ULONG NumberOfUnCommittedRanges;
 USHORT SegmentAllocatorBackTraceIndex;
 USHORT Reserved;
 LIST_ENTRY UCRSegmentList;
 ULONG Flags;
 ULONG ForceFlags;
 ULONG CompatibilityFlags;
 ULONG EncodeFlagMask;
 HEAP_ENTRY Encoding;
 ULONG PointerKey;
 ULONG Interceptor;
 ULONG VirtualMemoryThreshold;
 ULONG Signature;
 ULONG SegmentReserve;
 ULONG SegmentCommit;
 ULONG DeCommitFreeBlockThreshold;
 ULONG DeCommitTotalFreeThreshold;
 ULONG TotalFreeSize;
 ULONG MaximumAllocationSize;
 USHORT ProcessHeapsListIndex;
 USHORT HeaderValidateLength;
 PVOID HeaderValidateCopy;
 USHORT NextAvailableTagIndex;
 USHORT MaximumTagIndex;
 PHEAP_TAG_ENTRY TagEntries;
 LIST_ENTRY UCRList;
 ULONG AlignRound;
 ULONG AlignMask;
 LIST_ENTRY VirtualAllocdBlocks;
 LIST_ENTRY SegmentList;
 USHORT AllocatorBackTraceIndex;
 UINT8 gap_in_pdb_ofs_B2[0x2];
 ULONG NonDedicatedListLength;
 PVOID BlocksIndex;
 PVOID UCRIndex;
 PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
 LIST_ENTRY FreeLists;
 PHEAP_LOCK LockVariable;
 LONG (*CommitRoutine)(PVOID, PPVOID, PULONG);
 PVOID FrontEndHeap;
 USHORT FrontHeapLockCount;
 UCHAR FrontEndHeapType;
 UINT8 gap_in_pdb_ofs_DB[0x1];
 HEAP_COUNTERS Counters;
 HEAP_TUNING_PARAMETERS TuningParameters;

} __attribute__((packed)) HEAP, *PHEAP, **PPHEAP ;

typedef struct _HEAP_LOCK {
 union {
 RTL_CRITICAL_SECTION CriticalSection;
} Lock;

} __attribute__((packed)) HEAP_LOCK, *PHEAP_LOCK, **PPHEAP_LOCK ;

typedef struct _HEAP_USERDATA_HEADER {
union {
 SINGLE_LIST_ENTRY SFreeListEntry;
 struct {
  PHEAP_SUBSEGMENT SubSegment;
  PVOID Reserved;
  ULONG SizeIndex;
  ULONG Signature;
 };
};
} __attribute__((packed)) HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER ;

typedef struct _HEAP_SUBSEGMENT {
 PHEAP_LOCAL_SEGMENT_INFO LocalInfo;
 volatile PHEAP_USERDATA_HEADER UserBlocks;
 INTERLOCK_SEQ AggregateExchg;
 union {
  struct {
   USHORT BlockSize;
   USHORT Flags;
   USHORT BlockCount;
   UCHAR SizeIndex;
   UCHAR AffinityIndex;
  };
  ULONG Alignment[0x2];
 };
 SINGLE_LIST_ENTRY SFreeListEntry;
 volatile ULONG Lock;

} __attribute__((packed)) HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT ;

typedef struct _RTL_CRITICAL_SECTION_DEBUG {
 USHORT Type;
 USHORT CreatorBackTraceIndex;
 PRTL_CRITICAL_SECTION CriticalSection;
 LIST_ENTRY ProcessLocksList;
 ULONG EntryCount;
 ULONG ContentionCount;
 ULONG Flags;
 USHORT CreatorBackTraceIndexHigh;
 USHORT SpareUSHORT;

} __attribute__((packed)) RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, **PPRTL_CRITICAL_SECTION_DEBUG ;

typedef struct _HEAP_SEGMENT {
 HEAP_ENTRY Entry;
 ULONG SegmentSignature;
 ULONG SegmentFlags;
 LIST_ENTRY SegmentListEntry;
 PHEAP Heap;
 PVOID BaseAddress;
 ULONG NumberOfPages;
 PHEAP_ENTRY FirstEntry;
 PHEAP_ENTRY LastValidEntry;
 ULONG NumberOfUnCommittedPages;
 ULONG NumberOfUnCommittedRanges;
 USHORT SegmentAllocatorBackTraceIndex;
 USHORT Reserved;
 LIST_ENTRY UCRSegmentList;

} __attribute__((packed)) HEAP_SEGMENT, *PHEAP_SEGMENT, **PPHEAP_SEGMENT ;
