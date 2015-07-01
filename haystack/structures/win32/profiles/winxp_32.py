# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'i386-win']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 12
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 12:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*12

# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 4:
    POINTER_T = ctypes.POINTER
else:
    # required to access _ctypes
    import _ctypes
    # Emulate a pointer class using the approriate c_int32/c_int64 type
    # The new class should have :
    # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
    # but the class should be submitted to a unique instance for each base type
    # to that if A == B, POINTER_T(A) == POINTER_T(B)
    ctypes._pointer_t_type_cache = {}
    def POINTER_T(pointee):
        # a pointer should have the same length as LONG
        fake_ptr_base_type = ctypes.c_uint32 
        # specific case for c_void_p
        if pointee is None: # VOID pointer type. c_void_p.
            pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
            clsname = 'c_void'
        else:
            clsname = pointee.__name__
        if clsname in ctypes._pointer_t_type_cache:
            return ctypes._pointer_t_type_cache[clsname]
        # make template
        class _T(_ctypes._SimpleCData,):
            _type_ = 'I'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(4, clsname), (_T,),{}) 
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class



int8_t = ctypes.c_int8
int16_t = ctypes.c_int16
int32_t = ctypes.c_int32
int64_t = ctypes.c_int64
uint8_t = ctypes.c_uint8
uint16_t = ctypes.c_uint16
uint32_t = ctypes.c_uint32
uint64_t = ctypes.c_uint64
int_least8_t = ctypes.c_byte
int_least16_t = ctypes.c_int16
int_least32_t = ctypes.c_int32
int_least64_t = ctypes.c_int64
uint_least8_t = ctypes.c_ubyte
uint_least16_t = ctypes.c_uint16
uint_least32_t = ctypes.c_uint32
uint_least64_t = ctypes.c_uint64
int_fast8_t = ctypes.c_byte
int_fast16_t = ctypes.c_int32
int_fast32_t = ctypes.c_int32
int_fast64_t = ctypes.c_int64
uint_fast8_t = ctypes.c_ubyte
uint_fast16_t = ctypes.c_uint32
uint_fast32_t = ctypes.c_uint32
uint_fast64_t = ctypes.c_uint64
intptr_t = ctypes.c_int32
uintptr_t = ctypes.c_uint32
intmax_t = ctypes.c_int64
uintmax_t = ctypes.c_uint64
UINT8 = ctypes.c_ubyte
UCHAR = ctypes.c_ubyte
BOOL = ctypes.c_ubyte
CHAR = ctypes.c_byte
INT8 = ctypes.c_byte
WCHAR = ctypes.c_uint16
UINT16 = ctypes.c_uint16
USHORT = ctypes.c_uint16
SHORT = ctypes.c_int16
UINT32 = ctypes.c_uint32
ULONG = ctypes.c_uint32
LONG = ctypes.c_int32
UINT64 = ctypes.c_uint64
ULONGLONG = ctypes.c_uint64
LONGLONG = ctypes.c_int64
PVOID64 = ctypes.c_uint64
PPVOID64 = ctypes.c_uint64
PVOID32 = ctypes.c_uint32
PPVOID32 = ctypes.c_uint32
VOID = None
DOUBLE = ctypes.c_double
PUINT8 = POINTER_T(ctypes.c_ubyte)
PUCHAR = POINTER_T(ctypes.c_ubyte)
PBOOL = POINTER_T(ctypes.c_ubyte)
PCHAR = POINTER_T(ctypes.c_byte)
PINT8 = POINTER_T(ctypes.c_byte)
PUINT16 = POINTER_T(ctypes.c_uint16)
PUSHORT = POINTER_T(ctypes.c_uint16)
PSHORT = POINTER_T(ctypes.c_int16)
PUINT32 = POINTER_T(ctypes.c_uint32)
PULONG = POINTER_T(ctypes.c_uint32)
PLONG = POINTER_T(ctypes.c_int32)
PUINT64 = POINTER_T(ctypes.c_uint64)
PULONGLONG = POINTER_T(ctypes.c_uint64)
PLONGLONG = POINTER_T(ctypes.c_int64)
PVOID = POINTER_T(None)
PPVOID = POINTER_T(POINTER_T(None))
class struct__HEAP(ctypes.Structure):
    pass

class union__HEAP_1(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('FreeListsInUseTerminate', ctypes.c_uint16),
    ('DecommitCount', ctypes.c_uint16),
     ]

class struct__HEAP_UNCOMMMTTED_RANGE(ctypes.Structure):
    pass

struct__HEAP_UNCOMMMTTED_RANGE._pack_ = True # source:True
struct__HEAP_UNCOMMMTTED_RANGE._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('Address', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
    ('filler', ctypes.c_uint32),
]

class struct__HEAP_UCR_SEGMENT(ctypes.Structure):
    pass

struct__HEAP_UCR_SEGMENT._pack_ = True # source:True
struct__HEAP_UCR_SEGMENT._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UCR_SEGMENT)),
    ('ReservedSize', ctypes.c_uint32),
    ('CommittedSize', ctypes.c_uint32),
    ('filler', ctypes.c_uint32),
]

class struct__HEAP_PSEUDO_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
     ]

class struct__HEAP_SEGMENT(ctypes.Structure):
    pass

class struct__HEAP_ENTRY(ctypes.Structure):
    pass

class union__HEAP_ENTRY_0(ctypes.Union):
    pass

class struct__HEAP_ENTRY_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('PreviousSize', ctypes.c_uint16),
     ]

class struct__HEAP_ENTRY_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('SubSegmentCode', POINTER_T(None)),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('UnusedBytes', ctypes.c_ubyte),
    ('SegmentIndex', ctypes.c_ubyte),
     ]

union__HEAP_ENTRY_0._pack_ = True # source:False
union__HEAP_ENTRY_0._fields_ = [
    ('_0', struct__HEAP_ENTRY_0_0),
    ('_1', struct__HEAP_ENTRY_0_1),
]

struct__HEAP_ENTRY._pack_ = True # source:True
struct__HEAP_ENTRY._fields_ = [
    ('_0', union__HEAP_ENTRY_0),
]

HEAP_ENTRY = struct__HEAP_ENTRY
struct__HEAP_SEGMENT._pack_ = True # source:True
struct__HEAP_SEGMENT._fields_ = [
    ('Entry', HEAP_ENTRY),
    ('Signature', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('Heap', POINTER_T(struct__HEAP)),
    ('LargestUnCommittedRange', ctypes.c_uint32),
    ('BaseAddress', POINTER_T(None)),
    ('NumberOfPages', ctypes.c_uint32),
    ('FirstEntry', POINTER_T(struct__HEAP_ENTRY)),
    ('LastValidEntry', POINTER_T(struct__HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', ctypes.c_uint32),
    ('NumberOfUnCommittedRanges', ctypes.c_uint32),
    ('UnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('Reserved', ctypes.c_uint16),
    ('LastEntryInSegment', POINTER_T(struct__HEAP_ENTRY)),
]

class struct__LIST_ENTRY(ctypes.Structure):
    pass

struct__LIST_ENTRY._pack_ = True # source:True
struct__LIST_ENTRY._fields_ = [
    ('Flink', POINTER_T(struct__LIST_ENTRY)),
    ('Blink', POINTER_T(struct__LIST_ENTRY)),
]

LIST_ENTRY = struct__LIST_ENTRY
class struct__HEAP_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
    ('TagIndex', ctypes.c_uint16),
    ('CreatorBackTraceIndex', ctypes.c_uint16),
    ('TagName', ctypes.c_uint16 * 24),
     ]

class union__HEAP_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('FreeListsInUseUlong', ctypes.c_uint32 * 4),
    ('FreeListsInUseBytes', ctypes.c_ubyte * 16),
     ]

class struct__HEAP_LOCK(ctypes.Structure):
    pass

class union__HEAP_LOCK_0(ctypes.Union):
    pass

class struct__RTL_CRITICAL_SECTION(ctypes.Structure):
    pass

class struct__RTL_CRITICAL_SECTION_DEBUG(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Type', ctypes.c_uint16),
    ('CreatorBackTraceIndex', ctypes.c_uint16),
    ('CriticalSection', POINTER_T(struct__RTL_CRITICAL_SECTION)),
    ('ProcessLocksList', LIST_ENTRY),
    ('EntryCount', ctypes.c_uint32),
    ('ContentionCount', ctypes.c_uint32),
    ('Spare', ctypes.c_uint32 * 2),
     ]

struct__RTL_CRITICAL_SECTION._pack_ = True # source:True
struct__RTL_CRITICAL_SECTION._fields_ = [
    ('DebugInfo', POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)),
    ('LockCount', ctypes.c_int32),
    ('RecursionCount', ctypes.c_int32),
    ('OwningThread', POINTER_T(None)),
    ('LockSemaphore', POINTER_T(None)),
    ('SpinCount', ctypes.c_uint32),
]

RTL_CRITICAL_SECTION = struct__RTL_CRITICAL_SECTION
class struct__ERESOURCE(ctypes.Structure):
    pass

class struct__KSEMAPHORE(ctypes.Structure):
    pass

class struct__DISPATCHER_HEADER(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Type', ctypes.c_ubyte),
    ('Absolute', ctypes.c_ubyte),
    ('Size', ctypes.c_ubyte),
    ('Inserted', ctypes.c_ubyte),
    ('SignalState', ctypes.c_int32),
    ('WaitListHead', LIST_ENTRY),
     ]

DISPATCHER_HEADER = struct__DISPATCHER_HEADER
struct__KSEMAPHORE._pack_ = True # source:True
struct__KSEMAPHORE._fields_ = [
    ('Header', DISPATCHER_HEADER),
    ('Limit', ctypes.c_int32),
]

class union__ERESOURCE_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Address', POINTER_T(None)),
    ('CreatorBackTraceIndex', ctypes.c_uint32),
     ]

class struct__KEVENT(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Header', DISPATCHER_HEADER),
     ]

class struct__OWNER_ENTRY(ctypes.Structure):
    pass

class union__OWNER_ENTRY_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('OwnerCount', ctypes.c_int32),
    ('TableSize', ctypes.c_uint32),
     ]

struct__OWNER_ENTRY._pack_ = True # source:True
struct__OWNER_ENTRY._fields_ = [
    ('OwnerThread', ctypes.c_uint32),
    ('_1', union__OWNER_ENTRY_0),
]

struct__ERESOURCE._pack_ = True # source:True
struct__ERESOURCE._fields_ = [
    ('SystemResourcesList', LIST_ENTRY),
    ('OwnerTable', POINTER_T(struct__OWNER_ENTRY)),
    ('ActiveCount', ctypes.c_int16),
    ('Flag', ctypes.c_uint16),
    ('SharedWaiters', POINTER_T(struct__KSEMAPHORE)),
    ('ExclusiveWaiters', POINTER_T(struct__KEVENT)),
    ('OwnerThreads', struct__OWNER_ENTRY * 2),
    ('ContentionCount', ctypes.c_uint32),
    ('NumberOfSharedWaiters', ctypes.c_uint16),
    ('NumberOfExclusiveWaiters', ctypes.c_uint16),
    ('_10', union__ERESOURCE_0),
    ('SpinLock', ctypes.c_uint32),
]

ERESOURCE = struct__ERESOURCE
union__HEAP_LOCK_0._pack_ = True # source:False
union__HEAP_LOCK_0._fields_ = [
    ('CriticalSection', RTL_CRITICAL_SECTION),
    ('Resource', ERESOURCE),
]

struct__HEAP_LOCK._pack_ = True # source:True
struct__HEAP_LOCK._fields_ = [
    ('Lock', union__HEAP_LOCK_0),
]

struct__HEAP._pack_ = True # source:True
struct__HEAP._fields_ = [
    ('Entry', HEAP_ENTRY),
    ('Signature', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('ForceFlags', ctypes.c_uint32),
    ('VirtualMemoryThreshold', ctypes.c_uint32),
    ('SegmentReserve', ctypes.c_uint32),
    ('SegmentCommit', ctypes.c_uint32),
    ('DeCommitFreeBlockThreshold', ctypes.c_uint32),
    ('DeCommitTotalFreeThreshold', ctypes.c_uint32),
    ('TotalFreeSize', ctypes.c_uint32),
    ('MaximumAllocationSize', ctypes.c_uint32),
    ('ProcessHeapsListIndex', ctypes.c_uint16),
    ('HeaderValidateLength', ctypes.c_uint16),
    ('HeaderValidateCopy', POINTER_T(None)),
    ('NextAvailableTagIndex', ctypes.c_uint16),
    ('MaximumTagIndex', ctypes.c_uint16),
    ('TagEntries', POINTER_T(struct__HEAP_TAG_ENTRY)),
    ('UCRSegments', POINTER_T(struct__HEAP_UCR_SEGMENT)),
    ('UnusedUnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AlignRound', ctypes.c_uint32),
    ('AlignMask', ctypes.c_uint32),
    ('VirtualAllocdBlocks', LIST_ENTRY),
    ('Segments', POINTER_T(struct__HEAP_SEGMENT) * 64),
    ('u', union__HEAP_0),
    ('u2', union__HEAP_1),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('NonDedicatedListLength', ctypes.c_uint32),
    ('LargeBlocksIndex', POINTER_T(None)),
    ('PseudoTagEntries', POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', struct__LIST_ENTRY * 128),
    ('LockVariable', POINTER_T(struct__HEAP_LOCK)),
    ('CommitRoutine', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_int32, POINTER_T(None), POINTER_T(POINTER_T(None)), POINTER_T(ctypes.c_uint32)))),
    ('FrontEndHeap', POINTER_T(None)),
    ('FrontHeapLockCount', ctypes.c_uint16),
    ('FrontEndHeapType', ctypes.c_ubyte),
    ('LastSegmentIndex', ctypes.c_ubyte),
]

HEAP = struct__HEAP
PHEAP = POINTER_T(struct__HEAP)
PPHEAP = POINTER_T(POINTER_T(struct__HEAP))
HEAP_LOCK = struct__HEAP_LOCK
PHEAP_LOCK = POINTER_T(struct__HEAP_LOCK)
PPHEAP_LOCK = POINTER_T(POINTER_T(struct__HEAP_LOCK))
HEAP_SEGMENT = struct__HEAP_SEGMENT
PHEAP_SEGMENT = POINTER_T(struct__HEAP_SEGMENT)
PPHEAP_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_SEGMENT))
PRTL_CRITICAL_SECTION = POINTER_T(struct__RTL_CRITICAL_SECTION)
PPRTL_CRITICAL_SECTION = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION))
RTL_CRITICAL_SECTION_DEBUG = struct__RTL_CRITICAL_SECTION_DEBUG
PRTL_CRITICAL_SECTION_DEBUG = POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)
PPRTL_CRITICAL_SECTION_DEBUG = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG))
PLIST_ENTRY = POINTER_T(struct__LIST_ENTRY)
PPLIST_ENTRY = POINTER_T(POINTER_T(struct__LIST_ENTRY))
PPHEAP_UNCOMMMTTED_RANGE = POINTER_T(POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE))
HEAP_UNCOMMMTTED_RANGE = struct__HEAP_UNCOMMMTTED_RANGE
PHEAP_UNCOMMMTTED_RANGE = POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)
PPHEAP_ENTRY = POINTER_T(POINTER_T(struct__HEAP_ENTRY))
PHEAP_ENTRY = POINTER_T(struct__HEAP_ENTRY)
PHEAP_TAG_ENTRY = POINTER_T(struct__HEAP_TAG_ENTRY)
PPHEAP_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_TAG_ENTRY))
HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY
POWNER_ENTRY = POINTER_T(struct__OWNER_ENTRY)
OWNER_ENTRY = struct__OWNER_ENTRY
PPOWNER_ENTRY = POINTER_T(POINTER_T(struct__OWNER_ENTRY))
PPHEAP_PSEUDO_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY))
PHEAP_PSEUDO_TAG_ENTRY = POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)
HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY
class struct__SINGLE_LIST_ENTRY(ctypes.Structure):
    pass

struct__SINGLE_LIST_ENTRY._pack_ = True # source:True
struct__SINGLE_LIST_ENTRY._fields_ = [
    ('Next', POINTER_T(struct__SINGLE_LIST_ENTRY)),
]

SINGLE_LIST_ENTRY = struct__SINGLE_LIST_ENTRY
PSINGLE_LIST_ENTRY = POINTER_T(struct__SINGLE_LIST_ENTRY)
PPSINGLE_LIST_ENTRY = POINTER_T(POINTER_T(struct__SINGLE_LIST_ENTRY))
PHEAP_UCR_SEGMENT = POINTER_T(struct__HEAP_UCR_SEGMENT)
PPHEAP_UCR_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_UCR_SEGMENT))
HEAP_UCR_SEGMENT = struct__HEAP_UCR_SEGMENT
class union__SLIST_HEADER(ctypes.Union):
    pass

class struct__SLIST_HEADER_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Next', SINGLE_LIST_ENTRY),
    ('Depth', ctypes.c_uint16),
    ('Sequence', ctypes.c_uint16),
     ]

union__SLIST_HEADER._pack_ = True # source:True
union__SLIST_HEADER._fields_ = [
    ('Alignment', ctypes.c_uint64),
    ('_1', struct__SLIST_HEADER_0),
]

PPSLIST_HEADER = POINTER_T(POINTER_T(union__SLIST_HEADER))
SLIST_HEADER = union__SLIST_HEADER
PSLIST_HEADER = POINTER_T(union__SLIST_HEADER)
PDISPATCHER_HEADER = POINTER_T(struct__DISPATCHER_HEADER)
PPDISPATCHER_HEADER = POINTER_T(POINTER_T(struct__DISPATCHER_HEADER))
KEVENT = struct__KEVENT
PKEVENT = POINTER_T(struct__KEVENT)
PPKEVENT = POINTER_T(POINTER_T(struct__KEVENT))
PPKSEMAPHORE = POINTER_T(POINTER_T(struct__KSEMAPHORE))
PKSEMAPHORE = POINTER_T(struct__KSEMAPHORE)
KSEMAPHORE = struct__KSEMAPHORE
class struct__HEAP_FREE_ENTRY(ctypes.Structure):
    pass

class union__HEAP_FREE_ENTRY_0(ctypes.Union):
    pass

class struct__HEAP_FREE_ENTRY_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('PreviousSize', ctypes.c_uint16),
     ]

class struct__HEAP_FREE_ENTRY_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('SubSegmentCode', POINTER_T(None)),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('UnusedBytes', ctypes.c_ubyte),
    ('SegmentIndex', ctypes.c_ubyte),
    ('FreeList', LIST_ENTRY),
     ]

union__HEAP_FREE_ENTRY_0._pack_ = True # source:False
union__HEAP_FREE_ENTRY_0._fields_ = [
    ('_0', struct__HEAP_FREE_ENTRY_0_0),
    ('_1', struct__HEAP_FREE_ENTRY_0_1),
]

struct__HEAP_FREE_ENTRY._pack_ = True # source:True
struct__HEAP_FREE_ENTRY._fields_ = [
    ('_0', union__HEAP_FREE_ENTRY_0),
]

PPHEAP_FREE_ENTRY = POINTER_T(POINTER_T(struct__HEAP_FREE_ENTRY))
PHEAP_FREE_ENTRY = POINTER_T(struct__HEAP_FREE_ENTRY)
HEAP_FREE_ENTRY = struct__HEAP_FREE_ENTRY
PPERESOURCE = POINTER_T(POINTER_T(struct__ERESOURCE))
PERESOURCE = POINTER_T(struct__ERESOURCE)
class struct__HEAP_LOOKASIDE(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('ListHead', SLIST_HEADER),
    ('Depth', ctypes.c_uint16),
    ('MaximumDepth', ctypes.c_uint16),
    ('TotalAllocates', ctypes.c_uint32),
    ('AllocateMisses', ctypes.c_uint32),
    ('TotalFrees', ctypes.c_uint32),
    ('FreeMisses', ctypes.c_uint32),
    ('LastTotalAllocates', ctypes.c_uint32),
    ('LastAllocateMisses', ctypes.c_uint32),
    ('Counters', ctypes.c_uint32 * 2),
    ('gap_in_pdb_ofs_2C', ctypes.c_ubyte * 4),
     ]

HEAP_LOOKASIDE = struct__HEAP_LOOKASIDE
PPHEAP_LOOKASIDE = POINTER_T(POINTER_T(struct__HEAP_LOOKASIDE))
PHEAP_LOOKASIDE = POINTER_T(struct__HEAP_LOOKASIDE)
class struct__HEAP_SUBSEGMENT(ctypes.Structure):
    pass

class struct__INTERLOCK_SEQ(ctypes.Structure):
    pass

class union__INTERLOCK_SEQ_0(ctypes.Union):
    pass

class struct__INTERLOCK_SEQ_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Depth', ctypes.c_uint16),
    ('FreeEntryOffset', ctypes.c_uint16),
     ]

class struct__INTERLOCK_SEQ_0_2(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Exchg', ctypes.c_int64),
     ]

class struct__INTERLOCK_SEQ_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('OffsetAndDepth', ctypes.c_uint32),
    ('Sequence', ctypes.c_uint32),
     ]

union__INTERLOCK_SEQ_0._pack_ = True # source:False
union__INTERLOCK_SEQ_0._fields_ = [
    ('_0', struct__INTERLOCK_SEQ_0_0),
    ('_1', struct__INTERLOCK_SEQ_0_1),
    ('_2', struct__INTERLOCK_SEQ_0_2),
]

struct__INTERLOCK_SEQ._pack_ = True # source:True
struct__INTERLOCK_SEQ._fields_ = [
    ('_0', union__INTERLOCK_SEQ_0),
]

INTERLOCK_SEQ = struct__INTERLOCK_SEQ
class union__HEAP_SUBSEGMENT_0(ctypes.Union):
    pass

class struct__HEAP_SUBSEGMENT_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('BlockSize', ctypes.c_uint16),
    ('FreeThreshold', ctypes.c_uint16),
    ('BlockCount', ctypes.c_uint16),
    ('SizeIndex', ctypes.c_ubyte),
    ('AffinityIndex', ctypes.c_ubyte),
     ]

union__HEAP_SUBSEGMENT_0._pack_ = True # source:False
union__HEAP_SUBSEGMENT_0._fields_ = [
    ('_0', struct__HEAP_SUBSEGMENT_0_0),
    ('Alignment', ctypes.c_uint32 * 2),
]

class struct__HEAP_USERDATA_HEADER(ctypes.Structure):
    pass

class union__HEAP_USERDATA_HEADER_0(ctypes.Union):
    pass

class struct__HEAP_USERDATA_HEADER_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('SubSegment', POINTER_T(struct__HEAP_SUBSEGMENT)),
    ('HeapHandle', POINTER_T(None)),
    ('SizeIndex', ctypes.c_uint32),
    ('Signature', ctypes.c_uint32),
     ]

union__HEAP_USERDATA_HEADER_0._pack_ = True # source:False
union__HEAP_USERDATA_HEADER_0._fields_ = [
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('_1', struct__HEAP_USERDATA_HEADER_0_0),
]

struct__HEAP_USERDATA_HEADER._pack_ = True # source:True
struct__HEAP_USERDATA_HEADER._fields_ = [
    ('_0', union__HEAP_USERDATA_HEADER_0),
]

struct__HEAP_SUBSEGMENT._pack_ = True # source:True
struct__HEAP_SUBSEGMENT._fields_ = [
    ('Bucket', POINTER_T(None)),
    ('UserBlocks', POINTER_T(struct__HEAP_USERDATA_HEADER)),
    ('AggregateExchg', INTERLOCK_SEQ),
    ('_3', union__HEAP_SUBSEGMENT_0),
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('Lock', ctypes.c_uint32),
]

HEAP_SUBSEGMENT = struct__HEAP_SUBSEGMENT
PHEAP_SUBSEGMENT = POINTER_T(struct__HEAP_SUBSEGMENT)
PPHEAP_SUBSEGMENT = POINTER_T(POINTER_T(struct__HEAP_SUBSEGMENT))
HEAP_USERDATA_HEADER = struct__HEAP_USERDATA_HEADER
PHEAP_USERDATA_HEADER = POINTER_T(struct__HEAP_USERDATA_HEADER)
PPHEAP_USERDATA_HEADER = POINTER_T(POINTER_T(struct__HEAP_USERDATA_HEADER))
class struct_c__SA_SINGLE_LIST_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

class struct_c__SA_LIST_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

PINTERLOCK_SEQ = POINTER_T(struct__INTERLOCK_SEQ)
PPINTERLOCK_SEQ = POINTER_T(POINTER_T(struct__INTERLOCK_SEQ))
class struct_c__SA_HEAP_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

class struct__HEAP_ENTRY_EXTRA(ctypes.Structure):
    pass

class union__HEAP_ENTRY_EXTRA_0(ctypes.Union):
    pass

class struct__HEAP_ENTRY_EXTRA_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('TagIndex', ctypes.c_uint16),
    ('Settable', ctypes.c_uint32),
     ]

class struct__HEAP_ENTRY_EXTRA_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ZeroInit', ctypes.c_uint64),
     ]

union__HEAP_ENTRY_EXTRA_0._pack_ = True # source:False
union__HEAP_ENTRY_EXTRA_0._fields_ = [
    ('_0', struct__HEAP_ENTRY_EXTRA_0_0),
    ('_1', struct__HEAP_ENTRY_EXTRA_0_1),
]

struct__HEAP_ENTRY_EXTRA._pack_ = True # source:True
struct__HEAP_ENTRY_EXTRA._fields_ = [
    ('_0', union__HEAP_ENTRY_EXTRA_0),
]

PHEAP_ENTRY_EXTRA = POINTER_T(struct__HEAP_ENTRY_EXTRA)
HEAP_ENTRY_EXTRA = struct__HEAP_ENTRY_EXTRA
PPHEAP_ENTRY_EXTRA = POINTER_T(POINTER_T(struct__HEAP_ENTRY_EXTRA))
class union_c__UA_SLIST_HEADER(ctypes.Union):
    _pack_ = True # source:True
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

class struct__HEAP_VIRTUAL_ALLOC_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Entry', LIST_ENTRY),
    ('ExtraStuff', HEAP_ENTRY_EXTRA),
    ('CommitSize', ctypes.c_uint32),
    ('ReserveSize', ctypes.c_uint32),
    ('BusyBlock', HEAP_ENTRY),
     ]

HEAP_VIRTUAL_ALLOC_ENTRY = struct__HEAP_VIRTUAL_ALLOC_ENTRY
PPHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY))
PHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY)
__all__ = \
    ['struct__HEAP_SUBSEGMENT_0_0', 'struct__INTERLOCK_SEQ_0_0',
    'PPHEAP_UNCOMMMTTED_RANGE', 'HEAP_VIRTUAL_ALLOC_ENTRY', 'VOID',
    'HEAP_FREE_ENTRY', 'PUINT32', 'struct__HEAP_USERDATA_HEADER',
    'int_fast32_t', 'PPHEAP_SEGMENT', 'struct__HEAP_FREE_ENTRY_0_0',
    'PPSLIST_HEADER', 'struct__DISPATCHER_HEADER',
    'PHEAP_PSEUDO_TAG_ENTRY', 'uint8_t', 'PDISPATCHER_HEADER',
    'PPVOID', 'PVOID32', 'uint_least16_t', 'struct__HEAP_ENTRY_EXTRA',
    'UINT16', 'PPDISPATCHER_HEADER', 'PUSHORT', 'PUCHAR', 'intptr_t',
    'struct__OWNER_ENTRY', 'int_fast8_t', 'HEAP_TAG_ENTRY',
    'HEAP_ENTRY', 'PPHEAP_USERDATA_HEADER', 'RTL_CRITICAL_SECTION',
    'union__SLIST_HEADER', 'PPOWNER_ENTRY', 'struct__HEAP_SUBSEGMENT',
    'PPHEAP_TAG_ENTRY', 'union__OWNER_ENTRY_0', 'DOUBLE',
    'union__HEAP_1', 'union__HEAP_0', 'PPRTL_CRITICAL_SECTION_DEBUG',
    'INT8', 'uint_fast16_t', 'struct__HEAP_ENTRY', 'PINTERLOCK_SEQ',
    'SLIST_HEADER', 'PKSEMAPHORE', 'HEAP_UNCOMMMTTED_RANGE', 'PLONG',
    'LONGLONG', 'PHEAP_SEGMENT', 'SHORT', 'struct__SLIST_HEADER_0',
    'PINT8', 'KSEMAPHORE', 'intmax_t', 'int16_t', 'INTERLOCK_SEQ',
    'int_fast64_t', 'ERESOURCE', 'struct__HEAP_FREE_ENTRY_0_1',
    'struct_c__SA_LIST_ENTRY', 'ULONG', 'struct__HEAP',
    'int_least8_t', 'HEAP_USERDATA_HEADER', 'HEAP_LOOKASIDE',
    'struct__KSEMAPHORE', 'struct__INTERLOCK_SEQ',
    'struct__HEAP_LOCK', 'struct__SINGLE_LIST_ENTRY', 'PPHEAP',
    'struct__ERESOURCE', 'int_least16_t', 'UINT32', 'uint_least8_t',
    'struct__INTERLOCK_SEQ_0_1', 'PBOOL', 'struct__INTERLOCK_SEQ_0_2',
    'UCHAR', 'PPVOID32', 'PVOID64', 'union__HEAP_SUBSEGMENT_0',
    'struct__LIST_ENTRY', 'OWNER_ENTRY', 'PPHEAP_LOOKASIDE',
    'uint64_t', 'PHEAP_LOCK', 'PHEAP_TAG_ENTRY', 'HEAP_SEGMENT',
    'union__HEAP_FREE_ENTRY_0', 'PULONG', 'union__INTERLOCK_SEQ_0',
    'WCHAR', 'union__HEAP_ENTRY_EXTRA_0', 'uint16_t', 'uint_fast8_t',
    'PPERESOURCE', 'struct__RTL_CRITICAL_SECTION',
    'struct__HEAP_ENTRY_0_0', 'struct__HEAP_ENTRY_0_1', 'int32_t',
    'uint_least64_t', 'CHAR', 'LONG', 'PULONGLONG',
    'PSINGLE_LIST_ENTRY', 'HEAP_UCR_SEGMENT', 'PSLIST_HEADER',
    'PPHEAP_VIRTUAL_ALLOC_ENTRY', 'PUINT64', 'union__ERESOURCE_0',
    'struct__HEAP_LOOKASIDE', 'PRTL_CRITICAL_SECTION_DEBUG',
    'uint_least32_t', 'int_least64_t', 'struct__HEAP_SEGMENT',
    'KEVENT', 'struct__HEAP_VIRTUAL_ALLOC_ENTRY',
    'PPSINGLE_LIST_ENTRY', 'uintptr_t', 'PRTL_CRITICAL_SECTION',
    'struct_c__SA_SINGLE_LIST_ENTRY', 'PPHEAP_FREE_ENTRY',
    'RTL_CRITICAL_SECTION_DEBUG', 'struct__HEAP_ENTRY_EXTRA_0_1',
    'UINT8', 'int8_t', 'PPHEAP_PSEUDO_TAG_ENTRY', 'PLONGLONG',
    'PERESOURCE', 'DISPATCHER_HEADER', 'PKEVENT', 'PHEAP_FREE_ENTRY',
    'PPHEAP_LOCK', 'UINT64', 'PPHEAP_SUBSEGMENT',
    'PHEAP_UNCOMMMTTED_RANGE', 'struct__KEVENT', 'USHORT',
    'HEAP_ENTRY_EXTRA', 'union__HEAP_ENTRY_0',
    'HEAP_PSEUDO_TAG_ENTRY', 'BOOL', 'HEAP_LOCK', 'PPINTERLOCK_SEQ',
    'struct__HEAP_UCR_SEGMENT', 'LIST_ENTRY',
    'union__HEAP_USERDATA_HEADER_0', 'PUINT16', 'PHEAP', 'PPVOID64',
    'PLIST_ENTRY', 'uintmax_t', 'uint_fast32_t', 'PHEAP_SUBSEGMENT',
    'struct__HEAP_USERDATA_HEADER_0_0', 'int64_t', 'int_fast16_t',
    'PPLIST_ENTRY', 'PHEAP_LOOKASIDE', 'PHEAP_ENTRY_EXTRA',
    'union_c__UA_SLIST_HEADER', 'PHEAP_USERDATA_HEADER',
    'POWNER_ENTRY', 'PHEAP_UCR_SEGMENT', 'PPKSEMAPHORE',
    'struct__RTL_CRITICAL_SECTION_DEBUG', 'HEAP_SUBSEGMENT',
    'int_least32_t', 'PCHAR', 'struct_c__SA_HEAP_ENTRY', 'ULONGLONG',
    'PPHEAP_UCR_SEGMENT', 'PPHEAP_ENTRY_EXTRA',
    'struct__HEAP_TAG_ENTRY', 'PSHORT', 'PPKEVENT',
    'struct__HEAP_FREE_ENTRY', 'HEAP', 'PHEAP_VIRTUAL_ALLOC_ENTRY',
    'union__HEAP_LOCK_0', 'PUINT8', 'SINGLE_LIST_ENTRY',
    'struct__HEAP_PSEUDO_TAG_ENTRY', 'uint_fast64_t', 'PHEAP_ENTRY',
    'struct__HEAP_ENTRY_EXTRA_0_0', 'PPHEAP_ENTRY',
    'PPRTL_CRITICAL_SECTION', 'struct__HEAP_UNCOMMMTTED_RANGE',
    'uint32_t', 'PVOID']
