# 1 "WinXPSP3X86.ntdll.32.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 148 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "WinXPSP3X86.ntdll.32.h" 2






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
# 8 "WinXPSP3X86.ntdll.32.h" 2

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
# 60 "WinXPSP3X86.ntdll.32.h"
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

struct _HEAP_LOCK;
typedef struct _HEAP_LOCK HEAP_LOCK;
typedef HEAP_LOCK *PHEAP_LOCK, **PPHEAP_LOCK;

struct _HEAP_SEGMENT;
typedef struct _HEAP_SEGMENT HEAP_SEGMENT;
typedef HEAP_SEGMENT *PHEAP_SEGMENT, **PPHEAP_SEGMENT;

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

typedef struct _HEAP_UNCOMMMTTED_RANGE {
 struct _HEAP_UNCOMMMTTED_RANGE* Next;
 ULONG Address;
 ULONG Size;
 ULONG filler;

} __attribute__((packed)) HEAP_UNCOMMMTTED_RANGE, *PHEAP_UNCOMMMTTED_RANGE, **PPHEAP_UNCOMMMTTED_RANGE ;

typedef struct _HEAP_ENTRY {
union {
 struct {
  USHORT Size;
  USHORT PreviousSize;
 };
 struct {
  PVOID SubSegmentCode;
  UCHAR SmallTagIndex;
  UCHAR Flags;
  UCHAR UnusedBytes;
  volatile UCHAR SegmentIndex;
 };
};
} __attribute__((packed)) HEAP_ENTRY, *PHEAP_ENTRY, **PPHEAP_ENTRY ;

typedef struct _HEAP_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;
 USHORT TagIndex;
 USHORT CreatorBackTraceIndex;
 USHORT TagName[0x18];

} __attribute__((packed)) HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY, **PPHEAP_TAG_ENTRY ;

typedef struct _OWNER_ENTRY {
 ULONG OwnerThread;
 union {
  LONG OwnerCount;
  ULONG TableSize;
 };

} __attribute__((packed)) OWNER_ENTRY, *POWNER_ENTRY, **PPOWNER_ENTRY ;

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
 ULONG Allocs;
 ULONG Frees;
 ULONG Size;

} __attribute__((packed)) HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY, **PPHEAP_PSEUDO_TAG_ENTRY ;

typedef struct _SINGLE_LIST_ENTRY {
 struct _SINGLE_LIST_ENTRY* Next;

} __attribute__((packed)) SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY, **PPSINGLE_LIST_ENTRY ;

typedef struct _HEAP_UCR_SEGMENT {
 struct _HEAP_UCR_SEGMENT* Next;
 ULONG ReservedSize;
 ULONG CommittedSize;
 ULONG filler;

} __attribute__((packed)) HEAP_UCR_SEGMENT, *PHEAP_UCR_SEGMENT, **PPHEAP_UCR_SEGMENT ;

typedef union _SLIST_HEADER {
 ULONGLONG Alignment;
 struct {
  SINGLE_LIST_ENTRY Next;
  USHORT Depth;
  USHORT Sequence;
 };

} __attribute__((packed)) SLIST_HEADER, *PSLIST_HEADER, **PPSLIST_HEADER ;

typedef struct _DISPATCHER_HEADER {
 UCHAR Type;
 UCHAR Absolute;
 UCHAR Size;
 UCHAR Inserted;
 LONG SignalState;
 LIST_ENTRY WaitListHead;

} __attribute__((packed)) DISPATCHER_HEADER, *PDISPATCHER_HEADER, **PPDISPATCHER_HEADER ;

typedef struct _KEVENT {
 DISPATCHER_HEADER Header;

} __attribute__((packed)) KEVENT, *PKEVENT, **PPKEVENT ;

typedef struct _KSEMAPHORE {
 DISPATCHER_HEADER Header;
 LONG Limit;

} __attribute__((packed)) KSEMAPHORE, *PKSEMAPHORE, **PPKSEMAPHORE ;

typedef struct _HEAP_FREE_ENTRY {
union {
 struct {
  USHORT Size;
  USHORT PreviousSize;
 };
 struct {
  PVOID SubSegmentCode;
  UCHAR SmallTagIndex;
  UCHAR Flags;
  UCHAR UnusedBytes;
  volatile UCHAR SegmentIndex;
  LIST_ENTRY FreeList;
 };
};
} __attribute__((packed)) HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY, **PPHEAP_FREE_ENTRY ;

typedef struct _ERESOURCE {
 LIST_ENTRY SystemResourcesList;
 POWNER_ENTRY OwnerTable;
 SHORT ActiveCount;
 USHORT Flag;
 PKSEMAPHORE SharedWaiters;
 PKEVENT ExclusiveWaiters;
 OWNER_ENTRY OwnerThreads[0x2];
 ULONG ContentionCount;
 USHORT NumberOfSharedWaiters;
 USHORT NumberOfExclusiveWaiters;
 union {
  PVOID Address;
  ULONG CreatorBackTraceIndex;
 };
 ULONG SpinLock;

} __attribute__((packed)) ERESOURCE, *PERESOURCE, **PPERESOURCE ;

typedef struct _RTL_CRITICAL_SECTION {
 PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
 LONG LockCount;
 LONG RecursionCount;
 PVOID OwningThread;
 PVOID LockSemaphore;
 ULONG SpinCount;

} __attribute__((packed)) RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION, **PPRTL_CRITICAL_SECTION ;

typedef struct _HEAP_LOCK {
 union {
 RTL_CRITICAL_SECTION CriticalSection;
 ERESOURCE Resource;
} Lock;

} __attribute__((packed)) HEAP_LOCK, *PHEAP_LOCK, **PPHEAP_LOCK ;

typedef struct _HEAP_SEGMENT {
 HEAP_ENTRY Entry;
 ULONG Signature;
 ULONG Flags;
 PHEAP Heap;
 ULONG LargestUnCommittedRange;
 PVOID BaseAddress;
 ULONG NumberOfPages;
 PHEAP_ENTRY FirstEntry;
 PHEAP_ENTRY LastValidEntry;
 ULONG NumberOfUnCommittedPages;
 ULONG NumberOfUnCommittedRanges;
 PHEAP_UNCOMMMTTED_RANGE UnCommittedRanges;
 USHORT AllocatorBackTraceIndex;
 USHORT Reserved;
 PHEAP_ENTRY LastEntryInSegment;

} __attribute__((packed)) HEAP_SEGMENT, *PHEAP_SEGMENT, **PPHEAP_SEGMENT ;

typedef struct _RTL_CRITICAL_SECTION_DEBUG {
 USHORT Type;
 USHORT CreatorBackTraceIndex;
 PRTL_CRITICAL_SECTION CriticalSection;
 LIST_ENTRY ProcessLocksList;
 ULONG EntryCount;
 ULONG ContentionCount;
 ULONG Spare[0x2];

} __attribute__((packed)) RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, **PPRTL_CRITICAL_SECTION_DEBUG ;

typedef struct _HEAP {
 HEAP_ENTRY Entry;
 ULONG Signature;
 ULONG Flags;
 ULONG ForceFlags;
 ULONG VirtualMemoryThreshold;
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
 PHEAP_UCR_SEGMENT UCRSegments;
 PHEAP_UNCOMMMTTED_RANGE UnusedUnCommittedRanges;
 ULONG AlignRound;
 ULONG AlignMask;
 LIST_ENTRY VirtualAllocdBlocks;
 PHEAP_SEGMENT Segments[0x40];
 union {
 ULONG FreeListsInUseUlong[0x4];
 UCHAR FreeListsInUseBytes[0x10];
} u;
 union {
 USHORT FreeListsInUseTerminate;
 USHORT DecommitCount;
} u2;
 USHORT AllocatorBackTraceIndex;
 ULONG NonDedicatedListLength;
 PVOID LargeBlocksIndex;
 PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
 LIST_ENTRY FreeLists[0x80];
 PHEAP_LOCK LockVariable;
 LONG (*CommitRoutine)(PVOID, PPVOID, PULONG);
 PVOID FrontEndHeap;
 USHORT FrontHeapLockCount;
 UCHAR FrontEndHeapType;
 UCHAR LastSegmentIndex;

} __attribute__((packed)) HEAP, *PHEAP, **PPHEAP ;
# 1 "WinXPSP3X86.ntoskrnl.32.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 148 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "WinXPSP3X86.ntoskrnl.32.h" 2






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
# 8 "WinXPSP3X86.ntoskrnl.32.h" 2

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
# 60 "WinXPSP3X86.ntoskrnl.32.h"
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






struct _HEAP_LOOKASIDE;
typedef struct _HEAP_LOOKASIDE HEAP_LOOKASIDE;
typedef HEAP_LOOKASIDE *PHEAP_LOOKASIDE, **PPHEAP_LOOKASIDE;

struct _HEAP_SUBSEGMENT;
typedef struct _HEAP_SUBSEGMENT HEAP_SUBSEGMENT;
typedef HEAP_SUBSEGMENT *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT;

struct _HEAP_USERDATA_HEADER;
typedef struct _HEAP_USERDATA_HEADER HEAP_USERDATA_HEADER;
typedef HEAP_USERDATA_HEADER *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER;



typedef struct _SINGLE_LIST_ENTRY {
 struct _SINGLE_LIST_ENTRY* Next;

} __attribute__((packed)) SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY, **PPSINGLE_LIST_ENTRY ;

typedef struct _LIST_ENTRY {
 struct _LIST_ENTRY* Flink;
 struct _LIST_ENTRY* Blink;

} __attribute__((packed)) LIST_ENTRY, *PLIST_ENTRY, **PPLIST_ENTRY ;

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

typedef struct _HEAP_ENTRY {
union {
 struct {
  USHORT Size;
  USHORT PreviousSize;
 };
 struct {
  PVOID SubSegmentCode;
  UCHAR SmallTagIndex;
  UCHAR Flags;
  UCHAR UnusedBytes;
  volatile UCHAR SegmentIndex;
 };
};
} __attribute__((packed)) HEAP_ENTRY, *PHEAP_ENTRY, **PPHEAP_ENTRY ;

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

typedef union _SLIST_HEADER {
 ULONGLONG Alignment;
 struct {
  SINGLE_LIST_ENTRY Next;
  USHORT Depth;
  USHORT Sequence;
 };

} __attribute__((packed)) SLIST_HEADER, *PSLIST_HEADER, **PPSLIST_HEADER ;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY {
 LIST_ENTRY Entry;
 HEAP_ENTRY_EXTRA ExtraStuff;
 ULONG CommitSize;
 ULONG ReserveSize;
 HEAP_ENTRY BusyBlock;

} __attribute__((packed)) HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY, **PPHEAP_VIRTUAL_ALLOC_ENTRY ;

typedef struct _HEAP_USERDATA_HEADER {
union {
 SINGLE_LIST_ENTRY SFreeListEntry;
 struct {
  PHEAP_SUBSEGMENT SubSegment;
  PVOID HeapHandle;
  ULONG SizeIndex;
  ULONG Signature;
 };
};
} __attribute__((packed)) HEAP_USERDATA_HEADER, *PHEAP_USERDATA_HEADER, **PPHEAP_USERDATA_HEADER ;

typedef struct _HEAP_SUBSEGMENT {
 PVOID Bucket;
 volatile PHEAP_USERDATA_HEADER UserBlocks;
 INTERLOCK_SEQ AggregateExchg;
 union {
  struct {
   USHORT BlockSize;
   USHORT FreeThreshold;
   USHORT BlockCount;
   UCHAR SizeIndex;
   UCHAR AffinityIndex;
  };
  ULONG Alignment[0x2];
 };
 SINGLE_LIST_ENTRY SFreeListEntry;
 volatile ULONG Lock;

} __attribute__((packed)) HEAP_SUBSEGMENT, *PHEAP_SUBSEGMENT, **PPHEAP_SUBSEGMENT ;

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
