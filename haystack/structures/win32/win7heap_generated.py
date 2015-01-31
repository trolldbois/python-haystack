# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'x86_64-win64']
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes




VOID = None

class struct__LIST_ENTRY(ctypes.Structure):
    pass

struct__LIST_ENTRY._pack_ = True # source:False
struct__LIST_ENTRY._fields_ = [
    ('FLink', ctypes.POINTER(struct__LIST_ENTRY)),
    ('BLink', ctypes.POINTER(struct__LIST_ENTRY)),
]

PLIST_ENTRY = ctypes.POINTER(struct__LIST_ENTRY)

LIST_ENTRY = struct__LIST_ENTRY

class struct__LFH_BLOCK_ZONE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ListEntry', struct__LIST_ENTRY),
    ('FreePointer', ctypes.POINTER(None)),
    ('Limit', ctypes.POINTER(None)),
     ]

PLFH_BLOCK_ZONE = ctypes.POINTER(struct__LFH_BLOCK_ZONE)

LFH_BLOCK_ZONE = struct__LFH_BLOCK_ZONE

class struct__HEAP_PSEUDO_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
     ]

PHEAP_PSEUDO_TAG_ENTRY = ctypes.POINTER(struct__HEAP_PSEUDO_TAG_ENTRY)

HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY

class struct__HEAP_LOCK(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Lock', ctypes.c_uint32),
     ]

PHEAP_LOCK = ctypes.POINTER(struct__HEAP_LOCK)

HEAP_LOCK = struct__HEAP_LOCK

class struct_HEAPTABLE(ctypes.Structure):
    pass

class struct__HEAP(ctypes.Structure):
    pass

class struct__HEAP_LIST_LOOKUP(ctypes.Structure):
    pass

struct__HEAP_LIST_LOOKUP._pack_ = True # source:False
struct__HEAP_LIST_LOOKUP._fields_ = [
    ('ExtendedLookup', ctypes.POINTER(struct__HEAP_LIST_LOOKUP)),
    ('ArraySize', ctypes.c_uint32),
    ('ExtraItem', ctypes.c_uint32),
    ('ItemCount', ctypes.c_uint32),
    ('OutOfRangeItems', ctypes.c_uint32),
    ('BaseIndex', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ListHead', ctypes.POINTER(struct__LIST_ENTRY)),
    ('ListsInUseUlong', ctypes.POINTER(ctypes.c_uint32)),
    ('ListHints', ctypes.POINTER(ctypes.POINTER(struct__LIST_ENTRY))),
]

class struct__HEAP_COUNTERS(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('TotalMemoryReserved', ctypes.c_uint32),
    ('TotalMemoryCommitted', ctypes.c_uint32),
    ('TotalMemoryLargeUCR', ctypes.c_uint32),
    ('TotalSizeInVirtualBlocks', ctypes.c_uint32),
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
    ('InBlockDeccomitSize', ctypes.c_uint32),
    ('HighWatermarkSize', ctypes.c_uint32),
    ('LastPolledSize', ctypes.c_uint32),
     ]

class struct__HEAP_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
    ('TagIndex', ctypes.c_uint16),
    ('CreatorBackTraceIndex', ctypes.c_uint16),
    ('TagName', ctypes.c_uint16 * 24),
     ]

class struct__HEAP_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 16),
     ]

class struct__HEAP_SEGMENT(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Entry', struct__HEAP_ENTRY),
    ('SegmentSignature', ctypes.c_uint32),
    ('SegmentFlags', ctypes.c_uint32),
    ('SegmentListEntry', struct__LIST_ENTRY),
    ('Heap', ctypes.POINTER(struct__HEAP)),
    ('BaseAddress', ctypes.POINTER(None)),
    ('NumberOfPages', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('FirstEntry', ctypes.POINTER(struct__HEAP_ENTRY)),
    ('LastValidEntry', ctypes.POINTER(struct__HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', ctypes.c_uint32),
    ('NumberOfUnCommittedRanges', ctypes.c_uint32),
    ('SegmentAllocatorBackTraceIndex', ctypes.c_uint16),
    ('Reserved', ctypes.c_uint16),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('UCRSegmentList', struct__LIST_ENTRY),
     ]

class struct__HEAP_TUNING_PARAMETERS(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('CommittThresholdShift', ctypes.c_uint32),
    ('MaxPreCommittThreshold', ctypes.c_uint32),
     ]

struct__HEAP._pack_ = True # source:False
struct__HEAP._fields_ = [
    ('Segment', struct__HEAP_SEGMENT),
    ('Flags', ctypes.c_uint32),
    ('ForceFlags', ctypes.c_uint32),
    ('CompatibilityFlags', ctypes.c_uint32),
    ('EncodeFlagMask', ctypes.c_uint32),
    ('Encoding', struct__HEAP_ENTRY),
    ('PointerKey', ctypes.c_uint32),
    ('Interceptor', ctypes.c_uint32),
    ('VirtualMemoryThreshold', ctypes.c_uint32),
    ('Signature', ctypes.c_uint32),
    ('SegmentReserve', ctypes.c_uint32),
    ('SegmentCommit', ctypes.c_uint32),
    ('DeCommitFreeBlockThreshold', ctypes.c_uint32),
    ('DeCommitTotalFreeThreshold', ctypes.c_uint32),
    ('TotalFreeSize', ctypes.c_uint32),
    ('MaximumAllocationSize', ctypes.c_uint32),
    ('ProcessHeapsListIndex', ctypes.c_uint16),
    ('HeaderValidateLength', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('HeaderValidateCopy', ctypes.POINTER(None)),
    ('NextAvailableTagIndex', ctypes.c_uint16),
    ('MaximumTagIndex', ctypes.c_uint16),
    ('PADDING_1', ctypes.c_ubyte * 4),
    ('TagEntries', ctypes.POINTER(struct__HEAP_TAG_ENTRY)),
    ('UCRList', struct__LIST_ENTRY),
    ('AlignRound', ctypes.c_uint32),
    ('AlignMask', ctypes.c_uint32),
    ('VirtualAllocdBlocks', struct__LIST_ENTRY),
    ('SegmentList', struct__LIST_ENTRY),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('_PADDING0_', ctypes.c_ubyte * 2),
    ('NonDedicatedListLength', ctypes.c_uint32),
    ('BlocksIndex', ctypes.POINTER(struct__HEAP_LIST_LOOKUP)),
    ('UCRIndex', ctypes.POINTER(None)),
    ('PseudoTagEntries', ctypes.POINTER(struct__HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', struct__LIST_ENTRY),
    ('LockVariable', ctypes.POINTER(struct__HEAP_LOCK)),
    ('CommitRoutine', ctypes.POINTER(None)),
    ('FrontEndHeap', ctypes.POINTER(None)),
    ('FrontHeapLockCount', ctypes.c_uint16),
    ('FrontEndHeapType', ctypes.c_ubyte),
    ('_PADDING1_', ctypes.c_ubyte * 1),
    ('Counters', struct__HEAP_COUNTERS),
    ('TuningParameters', struct__HEAP_TUNING_PARAMETERS),
]

struct_HEAPTABLE._pack_ = True # source:False
struct_HEAPTABLE._fields_ = [
    ('list', ctypes.POINTER(struct__HEAP) * 16),
]

PHEAPTABLE = ctypes.POINTER(struct_HEAPTABLE)

HEAPTABLE = struct_HEAPTABLE

class struct__SLIST_HEADER(ctypes.Structure):
    pass

struct__SLIST_HEADER._pack_ = True # source:False
struct__SLIST_HEADER._fields_ = [
    ('Next', ctypes.POINTER(struct__SLIST_HEADER)),
    ('Depth', ctypes.c_uint16),
    ('Sequence', ctypes.c_uint16),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

SLIST_HEADER = struct__SLIST_HEADER

PSLIST_HEADER = ctypes.POINTER(struct__SLIST_HEADER)

class struct__SINGLE_LIST_ENTRY(ctypes.Structure):
    pass

struct__SINGLE_LIST_ENTRY._pack_ = True # source:False
struct__SINGLE_LIST_ENTRY._fields_ = [
    ('Next', ctypes.POINTER(struct__SINGLE_LIST_ENTRY)),
]

SINGLE_LIST_ENTRY = struct__SINGLE_LIST_ENTRY

PSINGLE_LIST_ENTRY = ctypes.POINTER(struct__SINGLE_LIST_ENTRY)

class union_c__S__HEAP_ENTRY_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('AgregateCode', ctypes.c_uint64),
    ('PADDING_0', ctypes.c_ubyte * 8),
     ]

class struct_c__S__HEAP_ENTRY_Ua_Sa(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('Flags', ctypes.c_ubyte),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('_PADDING0_', ctypes.c_ubyte * 4),
     ]

class union_c__S__HEAP_ENTRY_Ua_Sa_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('SegmentOffset', ctypes.c_ubyte),
    ('LFHFlags', ctypes.c_ubyte),
     ]

PHEAP_ENTRY = ctypes.POINTER(struct__HEAP_ENTRY)

HEAP_ENTRY = struct__HEAP_ENTRY

PHEAP_COUNTERS = ctypes.POINTER(struct__HEAP_COUNTERS)

HEAP_COUNTERS = struct__HEAP_COUNTERS

PHEAP_TUNING_PARAMETERS = ctypes.POINTER(struct__HEAP_TUNING_PARAMETERS)

HEAP_TUNING_PARAMETERS = struct__HEAP_TUNING_PARAMETERS

HEAP_SEGMENT = struct__HEAP_SEGMENT

PHEAP_SEGMENT = ctypes.POINTER(struct__HEAP_SEGMENT)

PHEAP = ctypes.POINTER(struct__HEAP)

HEAP = struct__HEAP

class struct__HEAP_ENTRY_EXTRA(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 8),
     ]

class union_c__S__HEAP_ENTRY_EXTRA_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('ZeroInit', ctypes.c_uint64),
     ]

class struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('TagIndex', ctypes.c_uint16),
    ('Settable', ctypes.c_uint32),
     ]

PHEAP_ENTRY_EXTRA = ctypes.POINTER(struct__HEAP_ENTRY_EXTRA)

HEAP_ENTRY_EXTRA = struct__HEAP_ENTRY_EXTRA

class struct__HEAP_FREE_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Entry', struct__HEAP_ENTRY),
    ('FreeList', struct__LIST_ENTRY),
     ]

PHEAP_FREE_ENTRY = ctypes.POINTER(struct__HEAP_FREE_ENTRY)

HEAP_FREE_ENTRY = struct__HEAP_FREE_ENTRY

HEAP_LIST_LOOKUP = struct__HEAP_LIST_LOOKUP

PHEAP_LIST_LOOKUP = ctypes.POINTER(struct__HEAP_LIST_LOOKUP)

class struct__HEAP_LOOKASIDE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ListHead', struct__SLIST_HEADER),
    ('Depth', ctypes.c_uint16),
    ('MaximumDepth', ctypes.c_uint16),
    ('TotalAllocates', ctypes.c_uint32),
    ('AllocateMisses', ctypes.c_uint32),
    ('TotalFrees', ctypes.c_uint32),
    ('FreeMisses', ctypes.c_uint32),
    ('LastTotalAllocates', ctypes.c_uint32),
    ('LastAllocateMisses', ctypes.c_uint32),
    ('Counters', ctypes.c_uint32 * 2),
    ('_PADDING0_', ctypes.c_ubyte * 4),
     ]

HEAP_LOOKASIDE = struct__HEAP_LOOKASIDE

PHEAP_LOOKASIDE = ctypes.POINTER(struct__HEAP_LOOKASIDE)

class struct__INTERLOCK_SEQ(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 8),
     ]

class union_c__S__INTERLOCK_SEQ_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('Exchg', ctypes.c_int64),
     ]

class struct_c__S__INTERLOCK_SEQ_Ua_Sa(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Depth', ctypes.c_uint16),
    ('FreeEntryOffset', ctypes.c_uint16),
    ('_PADDING0_', ctypes.c_ubyte * 4),
     ]

PINTERLOCK_SEQ = ctypes.POINTER(struct__INTERLOCK_SEQ)

INTERLOCK_SEQ = struct__INTERLOCK_SEQ

PHEAP_TAG_ENTRY = ctypes.POINTER(struct__HEAP_TAG_ENTRY)

HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY

class struct__HEAP_UCR_DESCRIPTOR(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ListEntry', struct__LIST_ENTRY),
    ('SegmentEntry', struct__LIST_ENTRY),
    ('Address', ctypes.POINTER(None)),
    ('Size', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
     ]

PHEAP_UCR_DESCRIPTOR = ctypes.POINTER(struct__HEAP_UCR_DESCRIPTOR)

HEAP_UCR_DESCRIPTOR = struct__HEAP_UCR_DESCRIPTOR

class struct__HEAP_USERDATA_HEADER(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 8),
    ('Reserved', ctypes.POINTER(None)),
    ('SizeIndex', ctypes.c_uint32),
    ('Signature', ctypes.c_uint32),
     ]

class union_c__S__HEAP_USERDATA_HEADER_Ua(ctypes.Union):
    pass

class struct__HEAP_SUBSEGMENT(ctypes.Structure):
    pass

class struct__HEAP_LOCAL_SEGMENT_INFO(ctypes.Structure):
    pass

class struct__HEAP_BUCKET_COUNTERS(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Foo', ctypes.c_uint32 * 2),
     ]

class struct__HEAP_LOCAL_DATA(ctypes.Structure):
    pass

class struct__LFH_HEAP(ctypes.Structure):
    pass

class struct__USER_MEMORY_CACHE_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Foo', ctypes.c_uint32 * 4),
     ]

class struct__HEAP_BUCKET(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Foo', ctypes.c_uint32),
     ]

struct__LFH_HEAP._pack_ = True # source:False
struct__LFH_HEAP._fields_ = [
    ('Lock', ctypes.c_uint32 * 6),
    ('SubSegmentZones', struct__LIST_ENTRY),
    ('ZoneBlockSize', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('Heap', ctypes.POINTER(None)),
    ('SegmentChange', ctypes.c_uint32),
    ('SegmentCreate', ctypes.c_uint32),
    ('SegmentInsertInFree', ctypes.c_uint32),
    ('SegmentDelete', ctypes.c_uint32),
    ('CacheAllocs', ctypes.c_uint32),
    ('CacheFrees', ctypes.c_uint32),
    ('SizeInCache', ctypes.c_uint32),
    ('RunInfo', ctypes.c_uint32 * 3),
    ('UserBlockCache', struct__USER_MEMORY_CACHE_ENTRY * 12),
    ('Buckets', struct__HEAP_BUCKET * 128),
    ('LocalData', struct__HEAP_LOCAL_DATA * 1),
]

struct__HEAP_LOCAL_DATA._pack_ = True # source:False
struct__HEAP_LOCAL_DATA._fields_ = [
    ('DeletedSubSegments', struct__SLIST_HEADER),
    ('CrtZone', ctypes.POINTER(struct__LFH_BLOCK_ZONE)),
    ('LowFragHeap', ctypes.POINTER(struct__LFH_HEAP)),
    ('Sequence', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('SegmentInfo', struct__HEAP_LOCAL_SEGMENT_INFO * 128),
]

struct__HEAP_LOCAL_SEGMENT_INFO._pack_ = True # source:False
struct__HEAP_LOCAL_SEGMENT_INFO._fields_ = [
    ('Hint', ctypes.POINTER(struct__HEAP_SUBSEGMENT)),
    ('ActiveSubsegment', ctypes.POINTER(struct__HEAP_SUBSEGMENT)),
    ('CachedItems', ctypes.POINTER(struct__HEAP_SUBSEGMENT) * 16),
    ('SListHeader', struct__SLIST_HEADER),
    ('Counters', struct__HEAP_BUCKET_COUNTERS),
    ('LocalData', ctypes.POINTER(struct__HEAP_LOCAL_DATA)),
    ('LastOpSequence', ctypes.c_uint32),
    ('BucketIndex', ctypes.c_uint16),
    ('LastUsed', ctypes.c_uint16),
    ('Pad', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

struct__HEAP_SUBSEGMENT._pack_ = True # source:False
struct__HEAP_SUBSEGMENT._fields_ = [
    ('LocalInfo', ctypes.POINTER(struct__HEAP_LOCAL_SEGMENT_INFO)),
    ('UserBlocks', ctypes.POINTER(struct__HEAP_USERDATA_HEADER)),
    ('AggregateExchg', struct__INTERLOCK_SEQ),
    ('BlockSize', ctypes.c_uint16),
    ('Flags', ctypes.c_uint16),
    ('BlockCount', ctypes.c_uint16),
    ('SizeIndex', ctypes.c_ubyte),
    ('AffinityIndex', ctypes.c_ubyte),
    ('SFreeListEntry', struct__SINGLE_LIST_ENTRY),
    ('Lock', ctypes.c_uint32),
    ('PADDING_0', ctypes.c_ubyte * 4),
]

union_c__S__HEAP_USERDATA_HEADER_Ua._pack_ = True # source:False
union_c__S__HEAP_USERDATA_HEADER_Ua._fields_ = [
    ('SFreeListEntry', struct__SINGLE_LIST_ENTRY),
    ('SubSegment', ctypes.POINTER(struct__HEAP_SUBSEGMENT)),
]

PHEAP_USERDATA_HEADER = ctypes.POINTER(struct__HEAP_USERDATA_HEADER)

HEAP_USERDATA_HEADER = struct__HEAP_USERDATA_HEADER

class struct__HEAP_VIRTUAL_ALLOC_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Entry', struct__LIST_ENTRY),
    ('ExtraStuff', struct__HEAP_ENTRY_EXTRA),
    ('CommitSize', ctypes.c_uint32),
    ('ReserveSize', ctypes.c_uint32),
    ('BusyBlock', struct__HEAP_ENTRY),
     ]

PHEAP_VIRTUAL_ALLOC_ENTRY = ctypes.POINTER(struct__HEAP_VIRTUAL_ALLOC_ENTRY)

HEAP_VIRTUAL_ALLOC_ENTRY = struct__HEAP_VIRTUAL_ALLOC_ENTRY

HEAP_LOCAL_SEGMENT_INFO = struct__HEAP_LOCAL_SEGMENT_INFO

PHEAP_LOCAL_SEGMENT_INFO = ctypes.POINTER(struct__HEAP_LOCAL_SEGMENT_INFO)

HEAP_LOCAL_DATA = struct__HEAP_LOCAL_DATA

HEAP_SUBSEGMENT = struct__HEAP_SUBSEGMENT

PHEAP_SUBSEGMENT = ctypes.POINTER(struct__HEAP_SUBSEGMENT)

LFH_HEAP = struct__LFH_HEAP

__all__ = ['struct__HEAP_VIRTUAL_ALLOC_ENTRY', 'PHEAP_SEGMENT',
           'PHEAP_SUBSEGMENT', 'struct__HEAP_UCR_DESCRIPTOR',
           'INTERLOCK_SEQ', 'PHEAP_FREE_ENTRY', 'PHEAP',
           'HEAP_ENTRY_EXTRA', 'VOID', 'struct__HEAP_COUNTERS',
           'HEAP_LOCAL_DATA', 'HEAP_SUBSEGMENT', 'PHEAP_LIST_LOOKUP',
           'struct__USER_MEMORY_CACHE_ENTRY',
           'struct__HEAP_USERDATA_HEADER', 'LFH_HEAP',
           'struct__SLIST_HEADER', 'PLFH_BLOCK_ZONE',
           'struct__HEAP_LOCAL_SEGMENT_INFO', 'HEAP_UCR_DESCRIPTOR',
           'union_c__S__INTERLOCK_SEQ_Ua', 'PHEAP_LOOKASIDE',
           'HEAP_TAG_ENTRY', 'PHEAP_PSEUDO_TAG_ENTRY', 'PHEAP_LOCK',
           'struct__HEAP', 'PSLIST_HEADER', 'struct__LFH_HEAP',
           'LFH_BLOCK_ZONE', 'HEAP_USERDATA_HEADER',
           'struct__LFH_BLOCK_ZONE', 'HEAP_LOOKASIDE',
           'struct__HEAP_LIST_LOOKUP', 'PSINGLE_LIST_ENTRY',
           'struct__HEAP_ENTRY_EXTRA', 'struct__HEAP_LOCK',
           'HEAPTABLE', 'struct__SINGLE_LIST_ENTRY',
           'struct_c__S__INTERLOCK_SEQ_Ua_Sa',
           'union_c__S__HEAP_ENTRY_Ua', 'PLIST_ENTRY', 'HEAP_ENTRY',
           'union_c__S__HEAP_ENTRY_Ua_Sa_Ua',
           'union_c__S__HEAP_USERDATA_HEADER_Ua',
           'struct_c__S__HEAP_ENTRY_Ua_Sa', 'struct__INTERLOCK_SEQ',
           'PHEAP_USERDATA_HEADER', 'struct__HEAP_LOOKASIDE',
           'struct__HEAP_SEGMENT', 'PHEAP_TUNING_PARAMETERS',
           'struct__HEAP_TAG_ENTRY', 'PHEAP_TAG_ENTRY',
           'struct__HEAP_BUCKET', 'HEAP_VIRTUAL_ALLOC_ENTRY',
           'struct__HEAP_FREE_ENTRY', 'HEAP', 'HEAP_FREE_ENTRY',
           'PHEAP_VIRTUAL_ALLOC_ENTRY', 'struct__HEAP_SUBSEGMENT',
           'struct__HEAP_TUNING_PARAMETERS',
           'PHEAP_LOCAL_SEGMENT_INFO', 'struct__LIST_ENTRY',
           'HEAP_TUNING_PARAMETERS', 'PHEAP_COUNTERS',
           'struct__HEAP_BUCKET_COUNTERS', 'SINGLE_LIST_ENTRY',
           'PHEAPTABLE', 'struct__HEAP_PSEUDO_TAG_ENTRY',
           'HEAP_LOCAL_SEGMENT_INFO', 'PHEAP_ENTRY_EXTRA',
           'struct__HEAP_LOCAL_DATA', 'PHEAP_UCR_DESCRIPTOR',
           'struct_HEAPTABLE', 'struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa',
           'HEAP_SEGMENT', 'union_c__S__HEAP_ENTRY_EXTRA_Ua',
           'HEAP_PSEUDO_TAG_ENTRY', 'HEAP_COUNTERS',
           'struct__HEAP_ENTRY', 'HEAP_LOCK', 'PINTERLOCK_SEQ',
           'SLIST_HEADER', 'LIST_ENTRY', 'PHEAP_ENTRY',
           'HEAP_LIST_LOOKUP']
