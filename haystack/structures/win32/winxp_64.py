# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-win64']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte * 16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte * 16

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
        if pointee is None:  # VOID pointer type. c_void_p.
            pointee = type(None)  # ctypes.c_void_p # ctypes.c_ulong
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
                return '%s(%d)' % (clsname, self.value)

            def contents(self):
                raise TypeError('This is not a ctypes pointer.')

            def __init__(self, **args):
                raise TypeError(
                    'This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s' % (8, clsname), (_T,), {})
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class


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
PPVOID = POINTER_T(POINTER_T(None))
PVOID = POINTER_T(None)


class struct__HEAP(ctypes.Structure):
    pass


class struct__HEAP_ENTRY(ctypes.Structure):
    pass


class union_c__S__HEAP_ENTRY_Ua_1(ctypes.Union):
    pass


class struct_c__S__HEAP_ENTRY_Ua_Sa_0(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('Size', ctypes.c_uint16),
        ('PreviousSize', ctypes.c_uint16),
        ('SmallTagIndex', ctypes.c_ubyte),
        ('Flags', ctypes.c_ubyte),
        ('UnusedBytes', ctypes.c_ubyte),
        ('SegmentIndex', ctypes.c_ubyte),
    ]


class struct_c__S__HEAP_ENTRY_Ua_Sa_1(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('CompactHeader', ctypes.c_uint64),
    ]

union_c__S__HEAP_ENTRY_Ua_1._pack_ = True  # source:False
union_c__S__HEAP_ENTRY_Ua_1._fields_ = [
    ('_0', struct_c__S__HEAP_ENTRY_Ua_Sa_0),
    ('_1', struct_c__S__HEAP_ENTRY_Ua_Sa_1),
]

struct__HEAP_ENTRY._pack_ = True  # source:True
struct__HEAP_ENTRY._fields_ = [
    ('PreviousBlockPrivateData', ctypes.c_uint64),
    ('_1', union_c__S__HEAP_ENTRY_Ua_1),
]

HEAP_ENTRY = struct__HEAP_ENTRY


class union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14555(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('FreeListsInUseTerminate', ctypes.c_uint16),
        ('DecommitCount', ctypes.c_uint16),
    ]


class union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14358(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('FreeListsInUseUlong', ctypes.c_uint32 * 4),
        ('FreeListsInUseBytes', ctypes.c_ubyte * 16),
    ]


class struct__HEAP_PSEUDO_TAG_ENTRY(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
        ('Allocs', ctypes.c_uint32),
        ('Frees', ctypes.c_uint32),
        ('Size', ctypes.c_uint64),
    ]


class struct__HEAP_LOCK(ctypes.Structure):
    pass


class union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_9852(
        ctypes.Union):
    pass


class struct__ERESOURCE(ctypes.Structure):
    pass


class struct__KEVENT(ctypes.Structure):
    pass


class struct__DISPATCHER_HEADER(ctypes.Structure):
    pass


class union_c__S__DISPATCHER_HEADER_Ua_0(ctypes.Union):
    pass


class struct_c__S__DISPATCHER_HEADER_Ua_Sa_0(ctypes.Structure):
    pass


class union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_3(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('Inserted', ctypes.c_ubyte),
        ('DebugActive', ctypes.c_ubyte),
    ]


class union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_2(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('Size', ctypes.c_ubyte),
        ('Hand', ctypes.c_ubyte),
    ]


class union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_1(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('Absolute', ctypes.c_ubyte),
        ('NpxIrql', ctypes.c_ubyte),
    ]

struct_c__S__DISPATCHER_HEADER_Ua_Sa_0._pack_ = True  # source:False
struct_c__S__DISPATCHER_HEADER_Ua_Sa_0._fields_ = [
    ('Type', ctypes.c_ubyte),
    ('_1', union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_1),
    ('_2', union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_2),
    ('_3', union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_3),
]


class struct_c__S__DISPATCHER_HEADER_Ua_Sa_1(ctypes.Structure):
    pass


class struct__LIST_ENTRY(ctypes.Structure):
    pass

struct__LIST_ENTRY._pack_ = True  # source:True
struct__LIST_ENTRY._fields_ = [
    ('Flink', POINTER_T(struct__LIST_ENTRY)),
    ('Blink', POINTER_T(struct__LIST_ENTRY)),
]

LIST_ENTRY = struct__LIST_ENTRY
struct_c__S__DISPATCHER_HEADER_Ua_Sa_1._pack_ = True  # source:False
struct_c__S__DISPATCHER_HEADER_Ua_Sa_1._fields_ = [
    ('Lock', ctypes.c_int32),
    ('SignalState', ctypes.c_int32),
    ('WaitListHead', LIST_ENTRY),
]

union_c__S__DISPATCHER_HEADER_Ua_0._pack_ = True  # source:False
union_c__S__DISPATCHER_HEADER_Ua_0._fields_ = [
    ('_0', struct_c__S__DISPATCHER_HEADER_Ua_Sa_0),
    ('_1', struct_c__S__DISPATCHER_HEADER_Ua_Sa_1),
]

struct__DISPATCHER_HEADER._pack_ = True  # source:True
struct__DISPATCHER_HEADER._fields_ = [
    ('_0', union_c__S__DISPATCHER_HEADER_Ua_0),
]

DISPATCHER_HEADER = struct__DISPATCHER_HEADER
struct__KEVENT._pack_ = True  # source:True
struct__KEVENT._fields_ = [
    ('Header', DISPATCHER_HEADER),
]


class struct__OWNER_ENTRY(ctypes.Structure):
    pass


class union_c__S__OWNER_ENTRY_Ua_1(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('OwnerCount', ctypes.c_int32),
        ('TableSize', ctypes.c_uint32),
    ]

struct__OWNER_ENTRY._pack_ = True  # source:True
struct__OWNER_ENTRY._fields_ = [
    ('OwnerThread', ctypes.c_uint64),
    ('_1', union_c__S__OWNER_ENTRY_Ua_1),
    ('gap_in_pdb_ofs_C', ctypes.c_ubyte * 4),
]


class union_c__S__ERESOURCE_Ua_11(ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('Address', ctypes.c_uint64),
        ('CreatorBackTraceIndex', ctypes.c_uint64),
    ]


class struct__KSEMAPHORE(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
        ('Header', DISPATCHER_HEADER),
        ('Limit', ctypes.c_int32),
        ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
    ]

struct__ERESOURCE._pack_ = True  # source:True
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
    ('_11', union_c__S__ERESOURCE_Ua_11),
    ('SpinLock', ctypes.c_uint64),
]

ERESOURCE = struct__ERESOURCE


class struct__RTL_CRITICAL_SECTION(ctypes.Structure):
    pass


class struct__RTL_CRITICAL_SECTION_DEBUG(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
        ('Type', ctypes.c_uint16),
        ('CreatorBackTraceIndex', ctypes.c_uint16),
        ('gap_in_pdb_ofs_4', ctypes.c_ubyte * 4),
        ('CriticalSection', POINTER_T(struct__RTL_CRITICAL_SECTION)),
        ('ProcessLocksList', LIST_ENTRY),
        ('EntryCount', ctypes.c_uint32),
        ('ContentionCount', ctypes.c_uint32),
        ('Spare', ctypes.c_uint32 * 2),
    ]

struct__RTL_CRITICAL_SECTION._pack_ = True  # source:True
struct__RTL_CRITICAL_SECTION._fields_ = [
    ('DebugInfo', POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)),
    ('LockCount', ctypes.c_int32),
    ('RecursionCount', ctypes.c_int32),
    ('OwningThread', ctypes.c_uint64),
    ('LockSemaphore', ctypes.c_uint64),
    ('SpinCount', ctypes.c_uint64),
]

RTL_CRITICAL_SECTION = struct__RTL_CRITICAL_SECTION
# source:False
union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_9852._pack_ = True
union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_9852._fields_ = [
    ('CriticalSection', RTL_CRITICAL_SECTION),
    ('Resource', ERESOURCE),
]

struct__HEAP_LOCK._pack_ = True  # source:True
struct__HEAP_LOCK._fields_ = [
    ('Lock', union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_9852),
]


class struct__HEAP_TAG_ENTRY(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
        ('Allocs', ctypes.c_uint32),
        ('Frees', ctypes.c_uint32),
        ('Size', ctypes.c_uint64),
        ('TagIndex', ctypes.c_uint16),
        ('CreatorBackTraceIndex', ctypes.c_uint16),
        ('TagName', ctypes.c_uint16 * 24),
        ('gap_in_pdb_ofs_44', ctypes.c_ubyte * 4),
    ]


class struct__HEAP_UNCOMMMTTED_RANGE(ctypes.Structure):
    pass

struct__HEAP_UNCOMMMTTED_RANGE._pack_ = True  # source:True
struct__HEAP_UNCOMMMTTED_RANGE._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('Address', ctypes.c_uint64),
    ('Size', ctypes.c_uint64),
    ('filler', ctypes.c_uint32),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
]


class struct__HEAP_SEGMENT(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
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


class struct__HEAP_UCR_SEGMENT(ctypes.Structure):
    pass

struct__HEAP_UCR_SEGMENT._pack_ = True  # source:True
struct__HEAP_UCR_SEGMENT._fields_ = [
    ('Next', POINTER_T(struct__HEAP_UCR_SEGMENT)),
    ('ReservedSize', ctypes.c_uint64),
    ('CommittedSize', ctypes.c_uint64),
    ('filler', ctypes.c_uint32),
    ('gap_in_pdb_ofs_1C', ctypes.c_ubyte * 4),
]

struct__HEAP._pack_ = True  # source:True
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
    ('u', union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14358),
    ('u2', union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14555),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('NonDedicatedListLength', ctypes.c_uint32),
    ('LargeBlocksIndex', ctypes.c_uint64),
    ('PseudoTagEntries', POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', struct__LIST_ENTRY * 128),
    ('LockVariable', POINTER_T(struct__HEAP_LOCK)),
    ('CommitRoutine',
     POINTER_T(ctypes.CFUNCTYPE(ctypes.c_int32,
                                ctypes.c_uint64,
                                ctypes.c_uint64,
                                POINTER_T(ctypes.c_uint64)))),
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
PHEAP_LOCK = POINTER_T(struct__HEAP_LOCK)
PPHEAP_LOCK = POINTER_T(POINTER_T(struct__HEAP_LOCK))
HEAP_SEGMENT = struct__HEAP_SEGMENT
PPHEAP_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_SEGMENT))
PHEAP_SEGMENT = POINTER_T(struct__HEAP_SEGMENT)
PPRTL_CRITICAL_SECTION = POINTER_T(POINTER_T(struct__RTL_CRITICAL_SECTION))
PRTL_CRITICAL_SECTION = POINTER_T(struct__RTL_CRITICAL_SECTION)
RTL_CRITICAL_SECTION_DEBUG = struct__RTL_CRITICAL_SECTION_DEBUG
PPRTL_CRITICAL_SECTION_DEBUG = POINTER_T(
    POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG))
PRTL_CRITICAL_SECTION_DEBUG = POINTER_T(struct__RTL_CRITICAL_SECTION_DEBUG)
PLIST_ENTRY = POINTER_T(struct__LIST_ENTRY)
PPLIST_ENTRY = POINTER_T(POINTER_T(struct__LIST_ENTRY))
HEAP_UNCOMMMTTED_RANGE = struct__HEAP_UNCOMMMTTED_RANGE
PHEAP_UNCOMMMTTED_RANGE = POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)
PPHEAP_UNCOMMMTTED_RANGE = POINTER_T(POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE))
PPHEAP_ENTRY = POINTER_T(POINTER_T(struct__HEAP_ENTRY))
PHEAP_ENTRY = POINTER_T(struct__HEAP_ENTRY)
PPHEAP_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_TAG_ENTRY))
HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY
PHEAP_TAG_ENTRY = POINTER_T(struct__HEAP_TAG_ENTRY)
POWNER_ENTRY = POINTER_T(struct__OWNER_ENTRY)
PPOWNER_ENTRY = POINTER_T(POINTER_T(struct__OWNER_ENTRY))
OWNER_ENTRY = struct__OWNER_ENTRY
HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY
PPHEAP_PSEUDO_TAG_ENTRY = POINTER_T(POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY))
PHEAP_PSEUDO_TAG_ENTRY = POINTER_T(struct__HEAP_PSEUDO_TAG_ENTRY)
PHEAP_UCR_SEGMENT = POINTER_T(struct__HEAP_UCR_SEGMENT)
HEAP_UCR_SEGMENT = struct__HEAP_UCR_SEGMENT
PPHEAP_UCR_SEGMENT = POINTER_T(POINTER_T(struct__HEAP_UCR_SEGMENT))
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
    _pack_ = True  # source:True
    _fields_ = [
        ('Alignment', ctypes.c_uint64),
        ('Region', ctypes.c_uint64),
    ]

PPSLIST_HEADER = POINTER_T(POINTER_T(struct__SLIST_HEADER))
SLIST_HEADER = struct__SLIST_HEADER
PSLIST_HEADER = POINTER_T(struct__SLIST_HEADER)


class struct__SINGLE_LIST_ENTRY(ctypes.Structure):
    pass

struct__SINGLE_LIST_ENTRY._pack_ = True  # source:True
struct__SINGLE_LIST_ENTRY._fields_ = [
    ('Next', POINTER_T(struct__SINGLE_LIST_ENTRY)),
]

PSINGLE_LIST_ENTRY = POINTER_T(struct__SINGLE_LIST_ENTRY)
SINGLE_LIST_ENTRY = struct__SINGLE_LIST_ENTRY
PPSINGLE_LIST_ENTRY = POINTER_T(POINTER_T(struct__SINGLE_LIST_ENTRY))


class struct__HEAP_SUBSEGMENT(ctypes.Structure):
    pass


class struct__HEAP_USERDATA_HEADER(ctypes.Structure):
    pass


class union_c__S__HEAP_USERDATA_HEADER_Ua_0(ctypes.Union):
    pass


class struct_c__S__HEAP_USERDATA_HEADER_Ua_Sa_1(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('SubSegment', POINTER_T(struct__HEAP_SUBSEGMENT)),
        ('HeapHandle', ctypes.c_uint64),
        ('SizeIndex', ctypes.c_uint64),
        ('Signature', ctypes.c_uint64),
    ]

union_c__S__HEAP_USERDATA_HEADER_Ua_0._pack_ = True  # source:False
union_c__S__HEAP_USERDATA_HEADER_Ua_0._fields_ = [
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('_1', struct_c__S__HEAP_USERDATA_HEADER_Ua_Sa_1),
]

struct__HEAP_USERDATA_HEADER._pack_ = True  # source:True
struct__HEAP_USERDATA_HEADER._fields_ = [
    ('_0', union_c__S__HEAP_USERDATA_HEADER_Ua_0),
]


class union_c__S__HEAP_SUBSEGMENT_Ua_3(ctypes.Union):
    pass


class struct_c__S__HEAP_SUBSEGMENT_Ua_Sa_0(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('BlockSize', ctypes.c_uint16),
        ('FreeThreshold', ctypes.c_uint16),
        ('BlockCount', ctypes.c_uint16),
        ('SizeIndex', ctypes.c_ubyte),
        ('AffinityIndex', ctypes.c_ubyte),
    ]

union_c__S__HEAP_SUBSEGMENT_Ua_3._pack_ = True  # source:False
union_c__S__HEAP_SUBSEGMENT_Ua_3._fields_ = [
    ('_0', struct_c__S__HEAP_SUBSEGMENT_Ua_Sa_0),
    ('Alignment', ctypes.c_uint32 * 2),
]


class struct__INTERLOCK_SEQ(ctypes.Structure):
    pass


class union_c__S__INTERLOCK_SEQ_Ua_0(ctypes.Union):
    pass


class struct_c__S__INTERLOCK_SEQ_Ua_Sa_1(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('OffsetAndDepth', ctypes.c_uint32),
        ('Sequence', ctypes.c_uint32),
    ]


class struct_c__S__INTERLOCK_SEQ_Ua_Sa_0(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('Depth', ctypes.c_uint16),
        ('FreeEntryOffset', ctypes.c_uint16),
    ]


class struct_c__S__INTERLOCK_SEQ_Ua_Sa_2(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('Exchg', ctypes.c_int64),
    ]

union_c__S__INTERLOCK_SEQ_Ua_0._pack_ = True  # source:False
union_c__S__INTERLOCK_SEQ_Ua_0._fields_ = [
    ('_0', struct_c__S__INTERLOCK_SEQ_Ua_Sa_0),
    ('_1', struct_c__S__INTERLOCK_SEQ_Ua_Sa_1),
    ('_2', struct_c__S__INTERLOCK_SEQ_Ua_Sa_2),
]

struct__INTERLOCK_SEQ._pack_ = True  # source:True
struct__INTERLOCK_SEQ._fields_ = [
    ('_0', union_c__S__INTERLOCK_SEQ_Ua_0),
]

INTERLOCK_SEQ = struct__INTERLOCK_SEQ
struct__HEAP_SUBSEGMENT._pack_ = True  # source:True
struct__HEAP_SUBSEGMENT._fields_ = [
    ('Bucket', ctypes.c_uint64),
    ('UserBlocks', POINTER_T(struct__HEAP_USERDATA_HEADER)),
    ('AggregateExchg', INTERLOCK_SEQ),
    ('_3', union_c__S__HEAP_SUBSEGMENT_Ua_3),
    ('SFreeListEntry', SINGLE_LIST_ENTRY),
    ('Lock', ctypes.c_uint32),
    ('gap_in_pdb_ofs_2C', ctypes.c_ubyte * 4),
]

HEAP_SUBSEGMENT = struct__HEAP_SUBSEGMENT
PHEAP_SUBSEGMENT = POINTER_T(struct__HEAP_SUBSEGMENT)
PPHEAP_SUBSEGMENT = POINTER_T(POINTER_T(struct__HEAP_SUBSEGMENT))
HEAP_USERDATA_HEADER = struct__HEAP_USERDATA_HEADER
PHEAP_USERDATA_HEADER = POINTER_T(struct__HEAP_USERDATA_HEADER)
PPHEAP_USERDATA_HEADER = POINTER_T(POINTER_T(struct__HEAP_USERDATA_HEADER))
PINTERLOCK_SEQ = POINTER_T(struct__INTERLOCK_SEQ)
PPINTERLOCK_SEQ = POINTER_T(POINTER_T(struct__INTERLOCK_SEQ))


class struct__HEAP_ENTRY_EXTRA(ctypes.Structure):
    pass


class union_c__S__HEAP_ENTRY_EXTRA_Ua_0(ctypes.Union):
    pass


class struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_0(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('AllocatorBackTraceIndex', ctypes.c_uint16),
        ('TagIndex', ctypes.c_uint16),
        ('PADDING_0', ctypes.c_ubyte * 4),
        ('Settable', ctypes.c_uint64),
    ]


class struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_1(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('ZeroInit', ctypes.c_uint64),
        ('ZeroInit1', ctypes.c_uint64),
    ]

union_c__S__HEAP_ENTRY_EXTRA_Ua_0._pack_ = True  # source:False
union_c__S__HEAP_ENTRY_EXTRA_Ua_0._fields_ = [
    ('_0', struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_0),
    ('_1', struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_1),
]

struct__HEAP_ENTRY_EXTRA._pack_ = True  # source:True
struct__HEAP_ENTRY_EXTRA._fields_ = [
    ('_0', union_c__S__HEAP_ENTRY_EXTRA_Ua_0),
]

PPHEAP_ENTRY_EXTRA = POINTER_T(POINTER_T(struct__HEAP_ENTRY_EXTRA))
HEAP_ENTRY_EXTRA = struct__HEAP_ENTRY_EXTRA
PHEAP_ENTRY_EXTRA = POINTER_T(struct__HEAP_ENTRY_EXTRA)


class struct__HEAP_LOOKASIDE(ctypes.Structure):
    _pack_ = True  # source:True
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

PPHEAP_LOOKASIDE = POINTER_T(POINTER_T(struct__HEAP_LOOKASIDE))
PHEAP_LOOKASIDE = POINTER_T(struct__HEAP_LOOKASIDE)
HEAP_LOOKASIDE = struct__HEAP_LOOKASIDE


class struct__HEAP_FREE_ENTRY(ctypes.Structure):
    pass


class union_c__S__HEAP_FREE_ENTRY_Ua_1(ctypes.Union):
    pass


class struct_c__S__HEAP_FREE_ENTRY_Ua_Sa_0(ctypes.Structure):
    _pack_ = True  # source:False
    _fields_ = [
        ('Size', ctypes.c_uint16),
        ('PreviousSize', ctypes.c_uint16),
        ('SmallTagIndex', ctypes.c_ubyte),
        ('Flags', ctypes.c_ubyte),
        ('UnusedBytes', ctypes.c_ubyte),
        ('SegmentIndex', ctypes.c_ubyte),
    ]

union_c__S__HEAP_FREE_ENTRY_Ua_1._pack_ = True  # source:False
union_c__S__HEAP_FREE_ENTRY_Ua_1._fields_ = [
    ('_0', struct_c__S__HEAP_FREE_ENTRY_Ua_Sa_0),
    ('CompactHeader', ctypes.c_uint64),
]

struct__HEAP_FREE_ENTRY._pack_ = True  # source:True
struct__HEAP_FREE_ENTRY._fields_ = [
    ('PreviousBlockPrivateData', ctypes.c_uint64),
    ('_1', union_c__S__HEAP_FREE_ENTRY_Ua_1),
    ('FreeList', LIST_ENTRY),
]

PHEAP_FREE_ENTRY = POINTER_T(struct__HEAP_FREE_ENTRY)
HEAP_FREE_ENTRY = struct__HEAP_FREE_ENTRY
PPHEAP_FREE_ENTRY = POINTER_T(POINTER_T(struct__HEAP_FREE_ENTRY))


class struct__HEAP_VIRTUAL_ALLOC_ENTRY(ctypes.Structure):
    _pack_ = True  # source:True
    _fields_ = [
        ('Entry', LIST_ENTRY),
        ('ExtraStuff', HEAP_ENTRY_EXTRA),
        ('CommitSize', ctypes.c_uint64),
        ('ReserveSize', ctypes.c_uint64),
        ('BusyBlock', HEAP_ENTRY),
    ]

PHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY)
HEAP_VIRTUAL_ALLOC_ENTRY = struct__HEAP_VIRTUAL_ALLOC_ENTRY
PPHEAP_VIRTUAL_ALLOC_ENTRY = POINTER_T(
    POINTER_T(struct__HEAP_VIRTUAL_ALLOC_ENTRY))


class union_c__S__HEAP_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_17600(
        ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('FreeListsInUseUlong', ctypes.c_uint32 * 4),
        ('FreeListsInUseBytes', ctypes.c_ubyte * 16),
    ]


class union_c__S__HEAP_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_17797(
        ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('FreeListsInUseTerminate', ctypes.c_uint16),
        ('DecommitCount', ctypes.c_uint16),
    ]


class union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_19030(
        ctypes.Union):
    _pack_ = True  # source:False
    _fields_ = [
        ('CriticalSection', RTL_CRITICAL_SECTION),
        ('Resource', ERESOURCE),
    ]

__all__ = \
    ['union_c__S__DISPATCHER_HEADER_Ua_0', 'PPHEAP_UNCOMMMTTED_RANGE',
     'HEAP_VIRTUAL_ALLOC_ENTRY', 'VOID', 'HEAP_FREE_ENTRY', 'PUINT32',
     'struct__HEAP_USERDATA_HEADER', 'struct__SLIST_HEADER',
     'INTERLOCK_SEQ', 'PPSLIST_HEADER', 'struct__DISPATCHER_HEADER',
     'PHEAP_PSEUDO_TAG_ENTRY', 'union_c__S__ERESOURCE_Ua_11',
     'PDISPATCHER_HEADER', 'PPVOID', 'PVOID32', 'PSINGLE_LIST_ENTRY',
     'struct__HEAP_ENTRY_EXTRA', 'UINT16', 'PPDISPATCHER_HEADER',
     'union_c__S__HEAP_USERDATA_HEADER_Ua_0', 'PUSHORT', 'PUCHAR',
     'union_c__S__HEAP_ENTRY_Ua_1',
     'union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_9852',
     'struct__OWNER_ENTRY', 'HEAP_TAG_ENTRY', 'struct__HEAP_SEGMENT',
     'struct_c__S__HEAP_SUBSEGMENT_Ua_Sa_0', 'RTL_CRITICAL_SECTION',
     'PPOWNER_ENTRY', 'PPHEAP_TAG_ENTRY', 'struct__HEAP_SUBSEGMENT',
     'DOUBLE', 'struct_c__S__INTERLOCK_SEQ_Ua_Sa_0',
     'struct_c__S__INTERLOCK_SEQ_Ua_Sa_1',
     'PPRTL_CRITICAL_SECTION_DEBUG', 'PHEAP_ENTRY_EXTRA',
     'struct__HEAP_ENTRY', 'PINTERLOCK_SEQ', 'SLIST_HEADER',
     'PKSEMAPHORE', 'HEAP_UNCOMMMTTED_RANGE', 'PLONG', 'LONGLONG',
     'PHEAP_SEGMENT', 'SHORT', 'union_c__S__HEAP_SUBSEGMENT_Ua_3',
     'PINT8', 'PPHEAP_ENTRY_EXTRA', 'PPHEAP_SEGMENT',
     'struct_c__S__INTERLOCK_SEQ_Ua_Sa_2',
     'union_c__S__HEAP_FREE_ENTRY_Ua_1', 'HEAP_SUBSEGMENT',
     'ERESOURCE', 'struct_c__S__DISPATCHER_HEADER_Ua_Sa_0',
     'struct_c__S__DISPATCHER_HEADER_Ua_Sa_1', 'ULONG', 'struct__HEAP',
     'HEAP_USERDATA_HEADER', 'HEAP_LOOKASIDE', 'struct__KSEMAPHORE',
     'struct__INTERLOCK_SEQ', 'struct__HEAP_LOCK',
     'struct__SINGLE_LIST_ENTRY', 'BOOL', 'struct__ERESOURCE',
     'UINT32', 'union_c__S__HEAP_ENTRY_EXTRA_Ua_0', 'PBOOL',
     'union_c__S__HEAP_LOCK_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_19030',
     'UCHAR', 'union_c__S__INTERLOCK_SEQ_Ua_0', 'USHORT', 'PPVOID32',
     'PVOID64', 'PHEAP_TAG_ENTRY', 'struct__LIST_ENTRY', 'OWNER_ENTRY',
     'PPHEAP_LOOKASIDE', 'PHEAP_LOCK', 'union_c__S__OWNER_ENTRY_Ua_1',
     'HEAP_SEGMENT', 'PULONG', 'WCHAR', 'PHEAP_ENTRY', 'PPERESOURCE',
     'struct__RTL_CRITICAL_SECTION', 'CHAR', 'LONG', 'PULONGLONG',
     'PPSINGLE_LIST_ENTRY', 'HEAP_UCR_SEGMENT', 'PSLIST_HEADER',
     'PPHEAP_VIRTUAL_ALLOC_ENTRY',
     'struct_c__S__HEAP_FREE_ENTRY_Ua_Sa_0', 'PUINT64',
     'struct__HEAP_LOOKASIDE', 'PRTL_CRITICAL_SECTION_DEBUG',
     'PHEAP_UNCOMMMTTED_RANGE', 'KEVENT',
     'struct__HEAP_VIRTUAL_ALLOC_ENTRY', 'KSEMAPHORE',
     'PRTL_CRITICAL_SECTION', 'PPHEAP_FREE_ENTRY',
     'RTL_CRITICAL_SECTION_DEBUG',
     'union_c__S__HEAP_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_17600',
     'UINT8', 'struct__HEAP_FREE_ENTRY', 'PPHEAP_PSEUDO_TAG_ENTRY',
     'PLONGLONG', 'PERESOURCE', 'DISPATCHER_HEADER',
     'PHEAP_FREE_ENTRY', 'PPHEAP_LOCK',
     'struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_1', 'UINT64',
     'PPHEAP_SUBSEGMENT', 'struct__HEAP_TAG_ENTRY', 'struct__KEVENT',
     'union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14555',
     'HEAP_ENTRY_EXTRA', 'HEAP_PSEUDO_TAG_ENTRY', 'PPHEAP',
     'HEAP_LOCK', 'PPINTERLOCK_SEQ', 'struct__HEAP_UCR_SEGMENT',
     'LIST_ENTRY', 'PUINT16', 'PHEAP', 'PPVOID64', 'PLIST_ENTRY',
     'PKEVENT', 'PHEAP_SUBSEGMENT', 'PPLIST_ENTRY',
     'struct_c__S__HEAP_USERDATA_HEADER_Ua_Sa_1',
     'union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_1',
     'union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_3',
     'union_c__S__DISPATCHER_HEADER_Ua_Sa_Ua_2',
     'struct_c__S__HEAP_ENTRY_Ua_Sa_1',
     'struct_c__S__HEAP_ENTRY_Ua_Sa_0', 'PHEAP_USERDATA_HEADER',
     'POWNER_ENTRY', 'PHEAP_UCR_SEGMENT',
     'struct__RTL_CRITICAL_SECTION_DEBUG', 'PHEAP_LOOKASIDE',
     'union_c__S__HEAP_U_Win2k3_XP64_X64DOTntdllDOT32DOTh_14358',
     'INT8', 'PCHAR', 'ULONGLONG', 'PPHEAP_UCR_SEGMENT', 'HEAP_ENTRY',
     'PSHORT', 'PPKEVENT', 'PPHEAP_USERDATA_HEADER', 'HEAP',
     'PHEAP_VIRTUAL_ALLOC_ENTRY', 'PUINT8',
     'union_c__S__HEAP_U_Win2k3_XP64_X64DOTntoskrnlDOT32DOTh_17797',
     'SINGLE_LIST_ENTRY', 'struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa_0',
     'struct__HEAP_PSEUDO_TAG_ENTRY', 'PPKSEMAPHORE', 'PPHEAP_ENTRY',
     'PPRTL_CRITICAL_SECTION', 'struct__HEAP_UNCOMMMTTED_RANGE',
     'PVOID']
