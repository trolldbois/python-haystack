# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-win64']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 8:
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
        fake_ptr_base_type = ctypes.c_uint64
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
            _type_ = 'L'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(8, clsname), (_T,),{})
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
int_fast16_t = ctypes.c_int64
int_fast32_t = ctypes.c_int64
int_fast64_t = ctypes.c_int64
uint_fast8_t = ctypes.c_ubyte
uint_fast16_t = ctypes.c_uint64
uint_fast32_t = ctypes.c_uint64
uint_fast64_t = ctypes.c_uint64
intptr_t = ctypes.c_int64
uintptr_t = ctypes.c_uint64
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
PPVOID32 = ctypes.c_uint32
PVOID32 = ctypes.c_uint32
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
PPVOID = POINTER_T(POINTER_T(None))
PVOID = POINTER_T(None)
class struct__HEAP(ctypes.Structure):
    pass

class union__HEAP_1(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('FreeListsInUseTerminate', ctypes.c_uint16),
    ('DecommitCount', ctypes.c_uint16),
     ]

class struct__HEAP_LOCK(ctypes.Structure):
    pass

class union__HEAP_LOCK_0(ctypes.Union):
    pass

class struct__RTL_CRITICAL_SECTION(ctypes.Structure):
    pass

class struct__RTL_CRITICAL_SECTION_DEBUG(ctypes.Structure):
    pass

class struct__LIST_ENTRY(ctypes.Structure):
    pass

struct__LIST_ENTRY._pack_ = True # source:True
struct__LIST_ENTRY._fields_ = [
    ('Flink', POINTER_T(struct__LIST_ENTRY)),
    ('Blink', POINTER_T(struct__LIST_ENTRY)),
]

LIST_ENTRY = struct__LIST_ENTRY
struct__RTL_CRITICAL_SECTION_DEBUG._pack_ = True # source:True
struct__RTL_CRITICAL_SECTION_DEBUG._fields_ = [
    ('Type', ctypes.c_uint16),
    ('CreatorBackTraceIndex', ctypes.c_uint16),
    ('gap_in_pdb_ofs_4', ctypes.c_ubyte * 4),
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
    ('OwningThread', ctypes.c_uint64),
    ('LockSemaphore', ctypes.c_uint64),
    ('SpinCount', ctypes.c_uint64),
]

RTL_CRITICAL_SECTION = struct__RTL_CRITICAL_SECTION
class struct__ERESOURCE(ctypes.Structure):
    pass

class union__ERESOURCE_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Address', ctypes.c_uint64),
    ('CreatorBackTraceIndex', ctypes.c_uint64),
     ]

class struct__KEVENT(ctypes.Structure):
    pass

class struct__DISPATCHER_HEADER(ctypes.Structure):
    pass

class union__DISPATCHER_HEADER_0(ctypes.Union):
    pass

class struct__DISPATCHER_HEADER_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Lock', ctypes.c_int32),
    ('SignalState', ctypes.c_int32),
    ('WaitListHead', LIST_ENTRY),
     ]

class struct__DISPATCHER_HEADER_0_0(ctypes.Structure):
    pass

class union__DISPATCHER_HEADER_0_0_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Absolute', ctypes.c_ubyte),
    ('NpxIrql', ctypes.c_ubyte),
     ]

class union__DISPATCHER_HEADER_0_0_2(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Inserted', ctypes.c_ubyte),
    ('DebugActive', ctypes.c_ubyte),
     ]

class union__DISPATCHER_HEADER_0_0_1(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_ubyte),
    ('Hand', ctypes.c_ubyte),
     ]

struct__DISPATCHER_HEADER_0_0._pack_ = True # source:False
struct__DISPATCHER_HEADER_0_0._fields_ = [
    ('Type', ctypes.c_ubyte),
    ('_1', union__DISPATCHER_HEADER_0_0_0),
    ('_2', union__DISPATCHER_HEADER_0_0_1),
    ('_3', union__DISPATCHER_HEADER_0_0_2),
]

union__DISPATCHER_HEADER_0._pack_ = True # source:False
union__DISPATCHER_HEADER_0._fields_ = [
    ('_0', struct__DISPATCHER_HEADER_0_0),
    ('_1', struct__DISPATCHER_HEADER_0_1),
]

struct__DISPATCHER_HEADER._pack_ = True # source:True
struct__DISPATCHER_HEADER._fields_ = [
    ('_0', union__DISPATCHER_HEADER_0),
]

DISPATCHER_HEADER = struct__DISPATCHER_HEADER
struct__KEVENT._pack_ = True # source:True
struct__KEVENT._fields_ = [
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
    ('OwnerThread', ctypes.c_uint64),
    ('_1', union__OWNER_ENTRY_0),
    ('gap_in_pdb_ofs_C', ctypes.c_ubyte * 4),
]

class struct__KSEMAPHORE(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Header', DISPATCHER_HEADER),
    ('Limit', ctypes.c_int32),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
     ]

struct__ERESOURCE._pack_ = True # source:True
struct__ERESOURCE._fields_ = [
    ('SystemResourcesList', LIST_ENTRY),
    ('OwnerTable', POINTER_T(struct__OWNER_ENTRY)),
    ('ActiveCount', ctypes.c_int16),
    ('Flag', ctypes.c_uint16),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
    ('SharedWaiters', POINTER_T(struct__KSEMAPHORE)),
    ('ExclusiveWaiters', POINTER_T(struct__KEVENT)),
    ('OwnerThreads', struct__OWNER_ENTRY * 2),
    ('ContentionCount', ctypes.c_uint32),
    ('NumberOfSharedWaiters', ctypes.c_uint16),
    ('NumberOfExclusiveWaiters', ctypes.c_uint16),
    ('_11', union__ERESOURCE_0),
    ('SpinLock', ctypes.c_uint64),
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

class struct__HEAP_ENTRY(ctypes.Structure):
    pass

class union__HEAP_ENTRY_0(ctypes.Union):
    pass

class struct__HEAP_ENTRY_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('PreviousSize', ctypes.c_uint16),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('UnusedBytes', ctypes.c_ubyte),
    ('SegmentIndex', ctypes.c_ubyte),
     ]

class struct__HEAP_ENTRY_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('CompactHeader', ctypes.c_uint64),
     ]

union__HEAP_ENTRY_0._pack_ = True # source:False
union__HEAP_ENTRY_0._fields_ = [
    ('_0', struct__HEAP_ENTRY_0_0),
    ('_1', struct__HEAP_ENTRY_0_1),
]

struct__HEAP_ENTRY._pack_ = True # source:True
struct__HEAP_ENTRY._fields_ = [
    ('PreviousBlockPrivateData', ctypes.c_uint64),
    ('_1', union__HEAP_ENTRY_0),
]

HEAP_ENTRY = struct__HEAP_ENTRY
class struct__HEAP_SEGMENT(ctypes.Structure):
    pass

class struct__HEAP_UNCOMMMTTED_RANGE(ctypes.Structure):
    pass

struct__HEAP_UNCOMMMTTED_RANGE._pack_ = True # source:True
struct__HEAP_UNCOMMMTTED_RANGE._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('Address', ctypes.c_uint64),
    ('Size', ctypes.c_uint64),
    ('filler', ctypes.c_uint32),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
]

struct__HEAP_SEGMENT._pack_ = True # source:True
struct__HEAP_SEGMENT._fields_ = [
    ('Entry', HEAP_ENTRY),
    ('Signature', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('Heap', POINTER_T(struct__HEAP)),
    ('LargestUnCommittedRange', ctypes.c_uint64),
    ('BaseAddress', ctypes.c_uint64),
    ('NumberOfPages', ctypes.c_uint32),
    ('gap_in_pdb_ofs_34', ctypes.c_ubyte * 4),
    ('FirstEntry', POINTER_T(struct__HEAP_ENTRY)),
    ('LastValidEntry', POINTER_T(struct__HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', ctypes.c_uint32),
    ('NumberOfUnCommittedRanges', ctypes.c_uint32),
    ('UnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('Reserved', ctypes.c_uint16),
    ('gap_in_pdb_ofs_5C', ctypes.c_ubyte * 4),
    ('LastEntryInSegment', POINTER_T(struct__HEAP_ENTRY)),
]

class union__HEAP_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('FreeListsInUseUlong', ctypes.c_uint32 * 4),
    ('FreeListsInUseBytes', ctypes.c_ubyte * 16),
     ]

class struct__HEAP_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint64),
    ('TagIndex', ctypes.c_uint16),
    ('CreatorBackTraceIndex', ctypes.c_uint16),
    ('TagName', ctypes.c_uint16 * 24),
    ('gap_in_pdb_ofs_44', ctypes.c_ubyte * 4),
     ]

class struct__HEAP_UCR_SEGMENT(ctypes.Structure):
    pass

struct__HEAP_UCR_SEGMENT._pack_ = True # source:True
struct__HEAP_UCR_SEGMENT._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UCR_SEGMENT)),
    ('ReservedSize', ctypes.c_uint64),
    ('CommittedSize', ctypes.c_uint64),
    ('filler', ctypes.c_uint32),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
]

class struct__HEAP_PSEUDO_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint64),
     ]

struct__HEAP._pack_ = True # source:True
struct__HEAP._fields_ = [
    ('Entry', HEAP_ENTRY),
    ('Signature', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('ForceFlags', ctypes.c_uint32),
    ('VirtualMemoryThreshold', ctypes.c_uint32),
    ('SegmentReserve', ctypes.c_uint64),
    ('SegmentCommit', ctypes.c_uint64),
    ('DeCommitFreeBlockThreshold', ctypes.c_uint64),
    ('DeCommitTotalFreeThreshold', ctypes.c_uint64),
    ('TotalFreeSize', ctypes.c_uint64),
    ('MaximumAllocationSize', ctypes.c_uint64),
    ('ProcessHeapsListIndex', ctypes.c_uint16),
    ('HeaderValidateLength', ctypes.c_uint16),
    ('gap_in_pdb_ofs_54', ctypes.c_ubyte * 4),
    ('HeaderValidateCopy', ctypes.c_uint64),
    ('NextAvailableTagIndex', ctypes.c_uint16),
    ('MaximumTagIndex', ctypes.c_uint16),
    ('gap_in_pdb_ofs_64', ctypes.c_ubyte * 4),
    ('TagEntries', POINTER_T(struct__HEAP_TAG_ENTRY)),
    ('UCRSegments', POINTER_T(struct__HEAP_UCR_SEGMENT)),
    ('UnusedUnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AlignRound', ctypes.c_uint64),
    ('AlignMask', ctypes.c_uint64),
    ('VirtualAllocdBlocks', LIST_ENTRY),
    ('Segments', POINTER_T(struct__HEAP_SEGMENT) * 64),
    ('u', union__HEAP_0),
    ('u2', union__HEAP_1),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('NonDedicatedListLength', ctypes.c_uint32),
    ('LargeBlocksIndex', ctypes.c_uint64),
    ('PseudoTagEntries', POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', struct__LIST_ENTRY * 128),
    ('LockVariable', POINTER_T(struct__HEAP_LOCK)),
    ('CommitRoutine', POINTER_T(ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_uint64, ctypes.c_uint64, POINTER_T(ctypes.c_uint64)))),
    ('FrontEndHeap', ctypes.c_uint64),
    ('FrontHeapLockCount', ctypes.c_uint16),
    ('FrontEndHeapType', ctypes.c_ubyte),
    ('LastSegmentIndex', ctypes.c_ubyte),
    ('gap_in_pdb_ofs_AE4', ctypes.c_ubyte * 4),
]

HEAP = struct__HEAP
PHEAP = POINTER_T(struct__HEAP)
PPHEAP = POINTER_T(POINTER_T(struct__HEAP))
HEAP_LOCK = struct__HEAP_LOCK
PPHEAP_LOCK = POINTER_T(POINTER_T(struct__HEAP_LOCK))
PHEAP_LOCK = POINTER_T(struct__HEAP_LOCK)
HEAP_SEGMENT = struct__HEAP_SEGMENT
PHEAP_SEGMENT = POINTER_T(struct__HEAP_SEGMENT)
PPHEAP_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_SEGMENT))
PPRTL_CRITICAL_SECTION = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION))
PRTL_CRITICAL_SECTION = POINTER_T(struct__RTL_CRITICAL_SECTION)
RTL_CRITICAL_SECTION_DEBUG = struct__RTL_CRITICAL_SECTION_DEBUG
PRTL_CRITICAL_SECTION_DEBUG = POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)
PPRTL_CRITICAL_SECTION_DEBUG = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG))
PPLIST_ENTRY = POINTER_T(POINTER_T(struct__LIST_ENTRY))
PLIST_ENTRY = POINTER_T(struct__LIST_ENTRY)
PHEAP_UNCOMMMTTED_RANGE = POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)
PPHEAP_UNCOMMMTTED_RANGE = POINTER_T(POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE))
HEAP_UNCOMMMTTED_RANGE = struct__HEAP_UNCOMMMTTED_RANGE
PPHEAP_ENTRY = POINTER_T(POINTER_T(struct__HEAP_ENTRY))
PHEAP_ENTRY = POINTER_T(struct__HEAP_ENTRY)
HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY
PHEAP_TAG_ENTRY = POINTER_T(struct__HEAP_TAG_ENTRY)
PPHEAP_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_TAG_ENTRY))
OWNER_ENTRY = struct__OWNER_ENTRY
POWNER_ENTRY = POINTER_T(struct__OWNER_ENTRY)
PPOWNER_ENTRY = POINTER_T(POINTER_T(struct__OWNER_ENTRY))
PPHEAP_PSEUDO_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY))
HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY
PHEAP_PSEUDO_TAG_ENTRY = POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)
PHEAP_UCR_SEGMENT = POINTER_T(struct__HEAP_UCR_SEGMENT)
PPHEAP_UCR_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_UCR_SEGMENT))
HEAP_UCR_SEGMENT = struct__HEAP_UCR_SEGMENT
PDISPATCHER_HEADER = POINTER_T(struct__DISPATCHER_HEADER)
PPDISPATCHER_HEADER = POINTER_T(POINTER_T(struct__DISPATCHER_HEADER))
KEVENT = struct__KEVENT
PKEVENT = POINTER_T(struct__KEVENT)
PPKEVENT = POINTER_T(POINTER_T(struct__KEVENT))
KSEMAPHORE = struct__KSEMAPHORE
PKSEMAPHORE = POINTER_T(struct__KSEMAPHORE)
PPKSEMAPHORE = POINTER_T(POINTER_T(struct__KSEMAPHORE))
PERESOURCE = POINTER_T(struct__ERESOURCE)
PPERESOURCE = POINTER_T(POINTER_T(struct__ERESOURCE))
class struct__SLIST_HEADER(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Alignment', ctypes.c_uint64),
    ('Region', ctypes.c_uint64),
     ]

SLIST_HEADER = struct__SLIST_HEADER
PSLIST_HEADER = POINTER_T(struct__SLIST_HEADER)
PPSLIST_HEADER = POINTER_T(POINTER_T(struct__SLIST_HEADER))
class struct__SINGLE_LIST_ENTRY(ctypes.Structure):
    pass

struct__SINGLE_LIST_ENTRY._pack_ = True # source:True
struct__SINGLE_LIST_ENTRY._fields_ = [
    ('Next', POINTER_T(struct__SINGLE_LIST_ENTRY)),
]

SINGLE_LIST_ENTRY = struct__SINGLE_LIST_ENTRY
PPSINGLE_LIST_ENTRY = POINTER_T(POINTER_T(struct__SINGLE_LIST_ENTRY))
PSINGLE_LIST_ENTRY = POINTER_T(struct__SINGLE_LIST_ENTRY)
class struct__HEAP_SUBSEGMENT(ctypes.Structure):
    pass

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
    ('HeapHandle', ctypes.c_uint64),
    ('SizeIndex', ctypes.c_uint64),
    ('Signature', ctypes.c_uint64),
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

class struct__INTERLOCK_SEQ(ctypes.Structure):
    pass

class union__INTERLOCK_SEQ_0(ctypes.Union):
    pass

class struct__INTERLOCK_SEQ_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('OffsetAndDepth', ctypes.c_uint32),
    ('Sequence', ctypes.c_uint32),
     ]

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
struct__HEAP_SUBSEGMENT._pack_ = True # source:True
struct__HEAP_SUBSEGMENT._fields_ = [
    ('Bucket', ctypes.c_uint64),
    ('UserBlocks', POINTER_T(struct__HEAP_USERDATA_HEADER)),
    ('AggregateExchg', INTERLOCK_SEQ),
    ('_3', union__HEAP_SUBSEGMENT_0),
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('Lock', ctypes.c_uint32),
    ('gap_in_pdb_ofs_2C', ctypes.c_ubyte * 4),
]

HEAP_SUBSEGMENT = struct__HEAP_SUBSEGMENT
PPHEAP_SUBSEGMENT = POINTER_T(POINTER_T(struct__HEAP_SUBSEGMENT))
PHEAP_SUBSEGMENT = POINTER_T(struct__HEAP_SUBSEGMENT)
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

class struct_c__SA_SLIST_HEADER(ctypes.Structure):
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
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('Settable', ctypes.c_uint64),
     ]

class struct__HEAP_ENTRY_EXTRA_0_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ZeroInit', ctypes.c_uint64),
    ('ZeroInit1', ctypes.c_uint64),
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
    ('gap_in_pdb_ofs_34', ctypes.c_ubyte * 12),
     ]

PHEAP_LOOKASIDE = POINTER_T(struct__HEAP_LOOKASIDE)
PPHEAP_LOOKASIDE = POINTER_T(POINTER_T(struct__HEAP_LOOKASIDE))
HEAP_LOOKASIDE = struct__HEAP_LOOKASIDE
class struct__HEAP_VIRTUAL_ALLOC_ENTRY(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('Entry', LIST_ENTRY),
    ('ExtraStuff', HEAP_ENTRY_EXTRA),
    ('CommitSize', ctypes.c_uint64),
    ('ReserveSize', ctypes.c_uint64),
    ('BusyBlock', HEAP_ENTRY),
     ]

HEAP_VIRTUAL_ALLOC_ENTRY = struct__HEAP_VIRTUAL_ALLOC_ENTRY
PPHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY))
PHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY)
__all__ = \
    ['struct__HEAP_SUBSEGMENT_0_0', 'struct__INTERLOCK_SEQ_0_0',
    'PPHEAP_UNCOMMMTTED_RANGE', 'HEAP_VIRTUAL_ALLOC_ENTRY', 'VOID',
    'PUINT32', 'struct__HEAP_USERDATA_HEADER', 'int_fast32_t',
    'PPHEAP_SEGMENT', 'struct__SLIST_HEADER', 'INTERLOCK_SEQ',
    'PPSLIST_HEADER', 'struct__DISPATCHER_HEADER',
    'PHEAP_PSEUDO_TAG_ENTRY', 'struct__DISPATCHER_HEADER_0_1',
    'struct__DISPATCHER_HEADER_0_0', 'uint8_t', 'PDISPATCHER_HEADER',
    'PPVOID', 'PVOID32', 'uint_least16_t', 'struct__HEAP_ENTRY_EXTRA',
    'UINT16', 'PPDISPATCHER_HEADER', 'PUSHORT', 'PUCHAR', 'intptr_t',
    'struct__OWNER_ENTRY', 'int_fast8_t', 'HEAP_TAG_ENTRY',
    'HEAP_ENTRY', 'PPHEAP_USERDATA_HEADER', 'RTL_CRITICAL_SECTION',
    'PPOWNER_ENTRY', 'struct__HEAP_SUBSEGMENT', 'PPHEAP_TAG_ENTRY',
    'union__OWNER_ENTRY_0', 'DOUBLE', 'union__HEAP_1',
    'union__HEAP_0', 'PPRTL_CRITICAL_SECTION_DEBUG', 'INT8',
    'uint_fast16_t', 'struct__HEAP_ENTRY', 'PINTERLOCK_SEQ',
    'SLIST_HEADER', 'PKSEMAPHORE', 'HEAP_UNCOMMMTTED_RANGE', 'PLONG',
    'LONGLONG', 'PHEAP_SEGMENT', 'SHORT', 'PULONGLONG', 'PINT8',
    'PPHEAP_ENTRY_EXTRA', 'intmax_t', 'int16_t', 'int_fast64_t',
    'ERESOURCE', 'struct_c__SA_LIST_ENTRY', 'ULONG', 'struct__HEAP',
    'union__DISPATCHER_HEADER_0_0_2', 'int_least8_t',
    'union__DISPATCHER_HEADER_0_0_0', 'HEAP_USERDATA_HEADER',
    'HEAP_LOOKASIDE', 'struct__KSEMAPHORE', 'struct__INTERLOCK_SEQ',
    'struct__HEAP_LOCK', 'struct__SINGLE_LIST_ENTRY', 'PPHEAP',
    'struct__ERESOURCE', 'int_least16_t', 'UINT32', 'uint_least8_t',
    'struct__INTERLOCK_SEQ_0_1', 'PBOOL', 'struct__INTERLOCK_SEQ_0_2',
    'UCHAR', 'PPVOID32', 'PVOID64', 'union__HEAP_SUBSEGMENT_0',
    'struct__LIST_ENTRY', 'OWNER_ENTRY', 'PPHEAP_LOOKASIDE',
    'uint64_t', 'PHEAP_LOCK', 'PHEAP_TAG_ENTRY', 'HEAP_SEGMENT',
    'PULONG', 'union__INTERLOCK_SEQ_0', 'WCHAR',
    'union__HEAP_ENTRY_EXTRA_0', 'uint16_t', 'uint_fast8_t',
    'PPERESOURCE', 'struct__RTL_CRITICAL_SECTION',
    'struct__HEAP_ENTRY_0_0', 'struct__HEAP_ENTRY_0_1', 'int32_t',
    'uint_least64_t', 'CHAR', 'LONG', 'union__DISPATCHER_HEADER_0',
    'PPSINGLE_LIST_ENTRY', 'PSINGLE_LIST_ENTRY', 'HEAP_UCR_SEGMENT',
    'PSLIST_HEADER', 'PPHEAP_VIRTUAL_ALLOC_ENTRY', 'PUINT64',
    'union__ERESOURCE_0', 'struct__HEAP_LOOKASIDE',
    'PRTL_CRITICAL_SECTION_DEBUG', 'uint_least32_t', 'int_least64_t',
    'KEVENT', 'struct__HEAP_VIRTUAL_ALLOC_ENTRY', 'KSEMAPHORE',
    'uintptr_t', 'PRTL_CRITICAL_SECTION',
    'struct_c__SA_SINGLE_LIST_ENTRY', 'RTL_CRITICAL_SECTION_DEBUG',
    'struct__HEAP_ENTRY_EXTRA_0_1', 'UINT8', 'int8_t',
    'PPHEAP_PSEUDO_TAG_ENTRY', 'PLONGLONG', 'PERESOURCE',
    'DISPATCHER_HEADER', 'PKEVENT', 'PPHEAP_LOCK',
    'struct__HEAP_PSEUDO_TAG_ENTRY', 'UINT64', 'PPHEAP_SUBSEGMENT',
    'PHEAP_UNCOMMMTTED_RANGE', 'struct__HEAP_TAG_ENTRY',
    'struct__KEVENT', 'USHORT', 'HEAP_ENTRY_EXTRA',
    'union__HEAP_ENTRY_0', 'HEAP_PSEUDO_TAG_ENTRY', 'BOOL',
    'HEAP_LOCK', 'PPINTERLOCK_SEQ', 'struct__HEAP_UCR_SEGMENT',
    'LIST_ENTRY', 'union__HEAP_USERDATA_HEADER_0', 'PUINT16', 'PHEAP',
    'PPVOID64', 'PLIST_ENTRY', 'uintmax_t', 'PHEAP_SUBSEGMENT',
    'struct__HEAP_USERDATA_HEADER_0_0', 'int64_t', 'int_fast16_t',
    'PPLIST_ENTRY', 'struct_c__SA_SLIST_HEADER', 'PHEAP_LOOKASIDE',
    'PHEAP_ENTRY_EXTRA', 'PHEAP_USERDATA_HEADER', 'POWNER_ENTRY',
    'PHEAP_UCR_SEGMENT', 'PPKSEMAPHORE',
    'struct__RTL_CRITICAL_SECTION_DEBUG', 'HEAP_SUBSEGMENT',
    'int_least32_t', 'PCHAR', 'struct_c__SA_HEAP_ENTRY', 'ULONGLONG',
    'PPHEAP_UCR_SEGMENT', 'struct__HEAP_SEGMENT', 'PSHORT',
    'PPKEVENT', 'HEAP', 'PHEAP_VIRTUAL_ALLOC_ENTRY',
    'union__HEAP_LOCK_0', 'PUINT8', 'SINGLE_LIST_ENTRY',
    'uint_fast32_t', 'uint_fast64_t', 'PHEAP_ENTRY',
    'struct__HEAP_ENTRY_EXTRA_0_0', 'PPHEAP_ENTRY',
    'PPRTL_CRITICAL_SECTION', 'struct__HEAP_UNCOMMMTTED_RANGE',
    'uint32_t', 'PVOID', 'union__DISPATCHER_HEADER_0_0_1']


'''
class struct__HEAP_COUNTERS(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('TotalMemoryReserved', ctypes.c_uint64),
    ('TotalMemoryCommitted', ctypes.c_uint64),
    ('TotalMemoryLargeUCR', ctypes.c_uint64),
    ('TotalSizeInVirtualBlocks', ctypes.c_uint64),
    ('TotalSegments', ctypes.c_uint32),
    ('TotalUCRs', ctypes.c_uint32),
    ('CommittOps', ctypes.c_uint32),
    ('DeCommitOps', ctypes.c_uint32),
    ('LockAcquires', ctypes.c_uint32),
    ('LockCollisions', ctypes.c_uint32),
    ('CommitRate', ctypes.c_uint32),
    ('DecommittRate', ctypes.c_uint32),
    ('CommitFailures', ctypes.c_uint32),
    ('InBlockCommitFailures', ctypes.c_uint32),
    ('CompactHeapCalls', ctypes.c_uint32),
    ('CompactedUCRs', ctypes.c_uint32),
    ('AllocAndFreeOps', ctypes.c_uint32),
    ('InBlockDeccommits', ctypes.c_uint32),
    ('InBlockDeccomitSize', ctypes.c_uint64),
    ('HighWatermarkSize', ctypes.c_uint64),
    ('LastPolledSize', ctypes.c_uint64),
     ]

HEAP_COUNTERS = struct__HEAP_COUNTERS

class struct__HEAP_TUNING_PARAMETERS(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('CommittThresholdShift', ctypes.c_uint32),
    ('gap_in_pdb_ofs_4', ctypes.c_ubyte * 4),
    ('MaxPreCommittThreshold', ctypes.c_uint64),
     ]

HEAP_TUNING_PARAMETERS = struct__HEAP_TUNING_PARAMETERS


class struct__HEAP_LOCAL_DATA(ctypes.Structure):
    pass

class struct__LFH_HEAP(ctypes.Structure):
    pass

class struct__USER_MEMORY_CACHE_ENTRY(ctypes.Structure):
    pass

class union__SLIST_HEADER(ctypes.Union):
    pass

class struct__SLIST_HEADER_3(ctypes.Structure):
    pass

class struct__SLIST_HEADER_3_0(ctypes.Structure):
    pass

class struct__SLIST_HEADER_3_0_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Depth', ctypes.c_uint16, 16),
    ('Sequence', ctypes.c_uint64, 48),
    ('HeaderType', ctypes.c_uint64, 1),
    ('Reserved', ctypes.c_uint64, 3),
    ('NextEntry', ctypes.c_uint64, 60),
     ]

struct__SLIST_HEADER_3_0._pack_ = True # source:False
struct__SLIST_HEADER_3_0._fields_ = [
    ('_0', struct__SLIST_HEADER_3_0_0),
]

struct__SLIST_HEADER_3._pack_ = True # source:False
struct__SLIST_HEADER_3._fields_ = [
    ('HeaderX64', struct__SLIST_HEADER_3_0),
]

class struct__SLIST_HEADER_2(ctypes.Structure):
    pass

class struct__SLIST_HEADER_2_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Depth', ctypes.c_uint16, 16),
    ('Sequence', ctypes.c_uint64, 48),
    ('HeaderType', ctypes.c_uint64, 1),
    ('Init', ctypes.c_uint64, 1),
    ('Reserved', ctypes.c_uint64, 2),
    ('NextEntry', ctypes.c_uint64, 60),
     ]

struct__SLIST_HEADER_2._pack_ = True # source:False
struct__SLIST_HEADER_2._fields_ = [
    ('_0', struct__SLIST_HEADER_2_0),
]

class struct__SLIST_HEADER_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Alignment', ctypes.c_uint64),
    ('Region', ctypes.c_uint64),
     ]

class struct__SLIST_HEADER_1(ctypes.Structure):
    pass

class struct__SLIST_HEADER_1_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Depth', ctypes.c_uint16, 16),
    ('Sequence', ctypes.c_uint64, 9),
    ('NextEntry', ctypes.c_uint64, 39),
    ('HeaderType', ctypes.c_uint64, 1),
    ('Init', ctypes.c_uint64, 1),
    ('Reserved', ctypes.c_uint64, 59),
    ('Region', ctypes.c_uint64, 3),
     ]

struct__SLIST_HEADER_1._pack_ = True # source:False
struct__SLIST_HEADER_1._fields_ = [
    ('_0', struct__SLIST_HEADER_1_0),
]

union__SLIST_HEADER._pack_ = True # source:True
union__SLIST_HEADER._fields_ = [
    ('_0', struct__SLIST_HEADER_0),
    ('Header8', struct__SLIST_HEADER_1),
    ('Header16', struct__SLIST_HEADER_2),
    ('_3', struct__SLIST_HEADER_3),
]

SLIST_HEADER = union__SLIST_HEADER
struct__USER_MEMORY_CACHE_ENTRY._pack_ = True # source:True
struct__USER_MEMORY_CACHE_ENTRY._fields_ = [
    ('UserBlocks', SLIST_HEADER),
    ('AvailableBlocks', ctypes.c_uint32),
    ('gap_in_pdb_ofs_14', ctypes.c_ubyte * 12),
]

class struct__HEAP_BUCKET(ctypes.Structure):
    pass

class struct__HEAP_BUCKET_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('UseAffinity', ctypes.c_uint8, 1),
    ('DebugFlags', ctypes.c_uint8, 2),
    ('PADDING_0', ctypes.c_uint8, 5),
     ]

struct__HEAP_BUCKET._pack_ = True # source:True
struct__HEAP_BUCKET._fields_ = [
    ('BlockUnits', ctypes.c_uint16),
    ('SizeIndex', ctypes.c_ubyte),
    ('_2', struct__HEAP_BUCKET_0),
]

class union__HEAP_BUCKET_RUN_INFO(ctypes.Union):
    pass

class struct__HEAP_BUCKET_RUN_INFO_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Aggregate64', ctypes.c_int64),
     ]

class struct__HEAP_BUCKET_RUN_INFO_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Bucket', ctypes.c_uint32),
    ('RunLength', ctypes.c_uint32),
     ]

union__HEAP_BUCKET_RUN_INFO._pack_ = True # source:True
union__HEAP_BUCKET_RUN_INFO._fields_ = [
    ('_0', struct__HEAP_BUCKET_RUN_INFO_0),
    ('_1', struct__HEAP_BUCKET_RUN_INFO_1),
]

HEAP_BUCKET_RUN_INFO = union__HEAP_BUCKET_RUN_INFO
struct__LFH_HEAP._pack_ = True # source:True
struct__LFH_HEAP._fields_ = [
    ('Lock', RTL_CRITICAL_SECTION),
    ('SubSegmentZones', LIST_ENTRY),
    ('ZoneBlockSize', ctypes.c_uint64),
    ('Heap', ctypes.c_uint64),
    ('SegmentChange', ctypes.c_uint32),
    ('SegmentCreate', ctypes.c_uint32),
    ('SegmentInsertInFree', ctypes.c_uint32),
    ('SegmentDelete', ctypes.c_uint32),
    ('CacheAllocs', ctypes.c_uint32),
    ('CacheFrees', ctypes.c_uint32),
    ('SizeInCache', ctypes.c_uint64),
    ('RunInfo', HEAP_BUCKET_RUN_INFO),
    ('UserBlockCache', struct__USER_MEMORY_CACHE_ENTRY * 12),
    ('Buckets', struct__HEAP_BUCKET * 128),
    ('LocalData', struct__HEAP_LOCAL_DATA * 1),
]

class struct__HEAP_LOCAL_SEGMENT_INFO(ctypes.Structure):
    pass

class struct__HEAP_SUBSEGMENT(ctypes.Structure):
    pass

class struct__SINGLE_LIST_ENTRY(ctypes.Structure):
    pass

struct__SINGLE_LIST_ENTRY._pack_ = True # source:True
struct__SINGLE_LIST_ENTRY._fields_ = [
    ('Next', POINTER_T(struct__SINGLE_LIST_ENTRY)),
]

SINGLE_LIST_ENTRY = struct__SINGLE_LIST_ENTRY
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
    ('Flags', ctypes.c_uint16),
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
    ('Reserved', ctypes.c_uint64),
    ('SizeIndex', ctypes.c_uint64),
    ('Signature', ctypes.c_uint64),
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
    ('LocalInfo', POINTER_T(struct__HEAP_LOCAL_SEGMENT_INFO)),
    ('UserBlocks', POINTER_T(struct__HEAP_USERDATA_HEADER)),
    ('AggregateExchg', INTERLOCK_SEQ),
    ('_3', union__HEAP_SUBSEGMENT_0),
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('Lock', ctypes.c_uint32),
    ('gap_in_pdb_ofs_2C', ctypes.c_ubyte * 4),
]

class union__HEAP_BUCKET_COUNTERS(ctypes.Union):
    pass

class struct__HEAP_BUCKET_COUNTERS_1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Aggregate64', ctypes.c_int64),
     ]

class struct__HEAP_BUCKET_COUNTERS_0(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('TotalBlocks', ctypes.c_uint32),
    ('SubSegmentCounts', ctypes.c_uint32),
     ]

union__HEAP_BUCKET_COUNTERS._pack_ = True # source:True
union__HEAP_BUCKET_COUNTERS._fields_ = [
    ('_0', struct__HEAP_BUCKET_COUNTERS_0),
    ('_1', struct__HEAP_BUCKET_COUNTERS_1),
]

HEAP_BUCKET_COUNTERS = union__HEAP_BUCKET_COUNTERS
struct__HEAP_LOCAL_SEGMENT_INFO._pack_ = True # source:True
struct__HEAP_LOCAL_SEGMENT_INFO._fields_ = [
    ('Hint', POINTER_T(struct__HEAP_SUBSEGMENT)),
    ('ActiveSubsegment', POINTER_T(struct__HEAP_SUBSEGMENT)),
    ('CachedItems', POINTER_T(struct__HEAP_SUBSEGMENT) * 16),
    ('SListHeader', SLIST_HEADER),
    ('Counters', HEAP_BUCKET_COUNTERS),
    ('LocalData', POINTER_T(struct__HEAP_LOCAL_DATA)),
    ('LastOpSequence', ctypes.c_uint32),
    ('BucketIndex', ctypes.c_uint16),
    ('LastUsed', ctypes.c_uint16),
    ('gap_in_pdb_ofs_B8', ctypes.c_ubyte * 8),
]

class struct__LFH_BLOCK_ZONE(ctypes.Structure):
    _pack_ = True # source:True
    _fields_ = [
    ('ListEntry', LIST_ENTRY),
    ('FreePointer', POINTER_T(None)),
    ('Limit', ctypes.c_uint64),
     ]

struct__HEAP_LOCAL_DATA._pack_ = True # source:True
struct__HEAP_LOCAL_DATA._fields_ = [
    ('DeletedSubSegments', SLIST_HEADER),
    ('CrtZone', POINTER_T(struct__LFH_BLOCK_ZONE)),
    ('LowFragHeap', POINTER_T(struct__LFH_HEAP)),
    ('Sequence', ctypes.c_uint32),
    ('gap_in_pdb_ofs_24', ctypes.c_ubyte * 12),
    ('SegmentInfo', struct__HEAP_LOCAL_SEGMENT_INFO * 128),
]

HEAP_LOCAL_DATA = struct__HEAP_LOCAL_DATA
PHEAP_LOCAL_DATA = POINTER_T(struct__HEAP_LOCAL_DATA)
PPHEAP_LOCAL_DATA = POINTER_T(POINTER_T(struct__HEAP_LOCAL_DATA))
HEAP_LOCAL_SEGMENT_INFO = struct__HEAP_LOCAL_SEGMENT_INFO
PPHEAP_LOCAL_SEGMENT_INFO = POINTER_T(POINTER_T(struct__HEAP_LOCAL_SEGMENT_INFO))
PHEAP_LOCAL_SEGMENT_INFO = POINTER_T(struct__HEAP_LOCAL_SEGMENT_INFO)
HEAP_LOCK = struct__HEAP_LOCK
PHEAP_LOCK = POINTER_T(struct__HEAP_LOCK)
PPHEAP_LOCK = POINTER_T(POINTER_T(struct__HEAP_LOCK))
HEAP_SUBSEGMENT = struct__HEAP_SUBSEGMENT
PPHEAP_SUBSEGMENT = POINTER_T(POINTER_T(struct__HEAP_SUBSEGMENT))
PHEAP_SUBSEGMENT = POINTER_T(struct__HEAP_SUBSEGMENT)
HEAP_USERDATA_HEADER = struct__HEAP_USERDATA_HEADER
PPHEAP_USERDATA_HEADER = POINTER_T(POINTER_T(struct__HEAP_USERDATA_HEADER))
PHEAP_USERDATA_HEADER = POINTER_T(struct__HEAP_USERDATA_HEADER)
LFH_HEAP = struct__LFH_HEAP
PLFH_HEAP = POINTER_T(struct__LFH_HEAP)
PPLFH_HEAP = POINTER_T(POINTER_T(struct__LFH_HEAP))
PPRTL_CRITICAL_SECTION = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION))
PRTL_CRITICAL_SECTION = POINTER_T(struct__RTL_CRITICAL_SECTION)
RTL_CRITICAL_SECTION_DEBUG = struct__RTL_CRITICAL_SECTION_DEBUG
PRTL_CRITICAL_SECTION_DEBUG = POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)
PPRTL_CRITICAL_SECTION_DEBUG = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG))
PLIST_ENTRY = POINTER_T(struct__LIST_ENTRY)
PPLIST_ENTRY = POINTER_T(POINTER_T(struct__LIST_ENTRY))
PSLIST_HEADER = POINTER_T(union__SLIST_HEADER)
PPSLIST_HEADER = POINTER_T(POINTER_T(union__SLIST_HEADER))
PSINGLE_LIST_ENTRY = POINTER_T(struct__SINGLE_LIST_ENTRY)
PPSINGLE_LIST_ENTRY = POINTER_T(POINTER_T(struct__SINGLE_LIST_ENTRY))
HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY
PPHEAP_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_TAG_ENTRY))
PHEAP_TAG_ENTRY = POINTER_T(struct__HEAP_TAG_ENTRY)
PHEAP_BUCKET_COUNTERS = POINTER_T(union__HEAP_BUCKET_COUNTERS)
PPHEAP_BUCKET_COUNTERS = POINTER_T(POINTER_T(union__HEAP_BUCKET_COUNTERS))
PPHEAP_BUCKET_RUN_INFO = POINTER_T(POINTER_T(union__HEAP_BUCKET_RUN_INFO))
PHEAP_BUCKET_RUN_INFO = POINTER_T(union__HEAP_BUCKET_RUN_INFO)
PINTERLOCK_SEQ = POINTER_T(struct__INTERLOCK_SEQ)
PPINTERLOCK_SEQ = POINTER_T(POINTER_T(struct__INTERLOCK_SEQ))
HEAP_BUCKET = struct__HEAP_BUCKET
PHEAP_BUCKET = POINTER_T(struct__HEAP_BUCKET)
PPHEAP_BUCKET = POINTER_T(POINTER_T(struct__HEAP_BUCKET))
PPHEAP_COUNTERS = POINTER_T(POINTER_T(struct__HEAP_COUNTERS))
PHEAP_COUNTERS = POINTER_T(struct__HEAP_COUNTERS)
PHEAP_PSEUDO_TAG_ENTRY = POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)
HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY
PPHEAP_PSEUDO_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY))
PPHEAP_ENTRY = POINTER_T(POINTER_T(struct__HEAP_ENTRY))
PHEAP_ENTRY = POINTER_T(struct__HEAP_ENTRY)
PPHEAP_TUNING_PARAMETERS = POINTER_T(POINTER_T(struct__HEAP_TUNING_PARAMETERS))
PHEAP_TUNING_PARAMETERS = POINTER_T(struct__HEAP_TUNING_PARAMETERS)
PLFH_BLOCK_ZONE = POINTER_T(struct__LFH_BLOCK_ZONE)
PPLFH_BLOCK_ZONE = POINTER_T(POINTER_T(struct__LFH_BLOCK_ZONE))
LFH_BLOCK_ZONE = struct__LFH_BLOCK_ZONE
USER_MEMORY_CACHE_ENTRY = struct__USER_MEMORY_CACHE_ENTRY
PPUSER_MEMORY_CACHE_ENTRY = POINTER_T(POINTER_T(struct__USER_MEMORY_CACHE_ENTRY))
PUSER_MEMORY_CACHE_ENTRY = POINTER_T(struct__USER_MEMORY_CACHE_ENTRY)
'''