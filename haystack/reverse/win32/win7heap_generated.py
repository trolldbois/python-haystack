from ctypes import *

STRING = c_char_p


VOID = None
class HEAPTABLE(Structure):
    pass
class _HEAP(Structure):
    pass
HEAPTABLE._fields_ = [
    ('list', POINTER(_HEAP) * 16),
]
class _LIST_ENTRY(Structure):
    pass
_LIST_ENTRY._fields_ = [
    ('FLink', POINTER(_LIST_ENTRY)),
    ('BLink', POINTER(_LIST_ENTRY)),
]
class _SLIST_HEADER(Structure):
    pass
__uint16_t = c_ushort
_SLIST_HEADER._fields_ = [
    ('Next', POINTER(_SLIST_HEADER)),
    ('Depth', __uint16_t),
    ('Sequence', __uint16_t),
]
PSLIST_HEADER = POINTER(_SLIST_HEADER)
SLIST_HEADER = _SLIST_HEADER
class _SINGLE_LIST_ENTRY(Structure):
    pass
_SINGLE_LIST_ENTRY._fields_ = [
    ('Next', POINTER(_SINGLE_LIST_ENTRY)),
]
class _HEAP_ENTRY(Structure):
    pass
class N11_HEAP_ENTRY3DOT_1E(Union):
    pass
class N11_HEAP_ENTRY3DOT_13DOT_2E(Structure):
    pass
__uint8_t = c_ubyte
N11_HEAP_ENTRY3DOT_13DOT_2E._fields_ = [
    ('Size', __uint16_t),
    ('Flags', __uint8_t),
    ('SmallTagIndex', __uint8_t),
    ('_PADDING0_', __uint8_t * 4),
]
class N11_HEAP_ENTRY3DOT_13DOT_3E(Structure):
    pass
class N11_HEAP_ENTRY3DOT_13DOT_33DOT_4E(Union):
    pass
N11_HEAP_ENTRY3DOT_13DOT_33DOT_4E._fields_ = [
    ('SegmentOffset', __uint8_t),
    ('LFHFlags', __uint8_t),
]
N11_HEAP_ENTRY3DOT_13DOT_3E._anonymous_ = ['_0']
N11_HEAP_ENTRY3DOT_13DOT_3E._fields_ = [
    ('SubSegmentCode', POINTER(VOID)),
    ('PreviousSize', __uint16_t),
    ('_0', N11_HEAP_ENTRY3DOT_13DOT_33DOT_4E),
    ('UnusedBytes', __uint8_t),
]
class N11_HEAP_ENTRY3DOT_13DOT_5E(Structure):
    pass
__uint32_t = c_uint
N11_HEAP_ENTRY3DOT_13DOT_5E._fields_ = [
    ('Code1', __uint32_t),
    ('Code2', __uint16_t),
    ('Code3', __uint8_t),
    ('Code4', __uint8_t),
]
__uint64_t = c_ulonglong
N11_HEAP_ENTRY3DOT_1E._pack_ = 4
N11_HEAP_ENTRY3DOT_1E._anonymous_ = ['_1', '_2', '_0']
N11_HEAP_ENTRY3DOT_1E._fields_ = [
    ('_0', N11_HEAP_ENTRY3DOT_13DOT_2E),
    ('_1', N11_HEAP_ENTRY3DOT_13DOT_3E),
    ('_2', N11_HEAP_ENTRY3DOT_13DOT_5E),
    ('AgregateCode', __uint64_t),
]
_HEAP_ENTRY._anonymous_ = ['_0']
_HEAP_ENTRY._fields_ = [
    ('_0', N11_HEAP_ENTRY3DOT_1E),
]
PHEAP_ENTRY = POINTER(_HEAP_ENTRY)
HEAP_ENTRY = _HEAP_ENTRY
class _HEAP_COUNTERS(Structure):
    pass
_HEAP_COUNTERS._fields_ = [
    ('TotalMemoryReserved', __uint32_t),
    ('TotalMemoryCommitted', __uint32_t),
    ('TotalMemoryLargeUCR', __uint32_t),
    ('TotalSizeInVirtualBlocks', __uint32_t),
    ('TotalSegments', __uint32_t),
    ('TotalUCRs', __uint32_t),
    ('CommittOps', __uint32_t),
    ('DeCommitOps', __uint32_t),
    ('LockAcquires', __uint32_t),
    ('LockCollisions', __uint32_t),
    ('CommitRate', __uint32_t),
    ('DecommittRate', __uint32_t),
    ('CommitFailures', __uint32_t),
    ('InBlockCommitFailures', __uint32_t),
    ('CompactHeapCalls', __uint32_t),
    ('CompactedUCRs', __uint32_t),
    ('AllocAndFreeOps', __uint32_t),
    ('InBlockDeccommits', __uint32_t),
    ('InBlockDeccomitSize', __uint32_t),
    ('HighWatermarkSize', __uint32_t),
    ('LastPolledSize', __uint32_t),
]
HEAP_COUNTERS = _HEAP_COUNTERS
PHEAP_COUNTERS = POINTER(_HEAP_COUNTERS)
class _HEAP_TUNING_PARAMETERS(Structure):
    pass
_HEAP_TUNING_PARAMETERS._fields_ = [
    ('CommittThresholdShift', __uint32_t),
    ('MaxPreCommittThreshold', __uint32_t),
]
HEAP_TUNING_PARAMETERS = _HEAP_TUNING_PARAMETERS
PHEAP_TUNING_PARAMETERS = POINTER(_HEAP_TUNING_PARAMETERS)
class _HEAP_SEGMENT(Structure):
    pass
_HEAP_SEGMENT._fields_ = [
    ('Entry', _HEAP_ENTRY),
    ('SegmentSignature', __uint32_t),
    ('SegmentFlags', __uint32_t),
    ('SegmentListEntry', _LIST_ENTRY),
    ('Heap', POINTER(_HEAP)),
    ('BaseAddress', POINTER(VOID)),
    ('NumberOfPages', __uint32_t),
    ('FirstEntry', POINTER(_HEAP_ENTRY)),
    ('LastValidEntry', POINTER(_HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', __uint32_t),
    ('NumberOfUnCommittedRanges', __uint32_t),
    ('SegmentAllocatorBackTraceIndex', __uint16_t),
    ('Reserved', __uint16_t),
    ('UCRSegmentList', _LIST_ENTRY),
]
HEAP_SEGMENT = _HEAP_SEGMENT
PHEAP_SEGMENT = POINTER(_HEAP_SEGMENT)
class _HEAP_TAG_ENTRY(Structure):
    pass
class _HEAP_PSEUDO_TAG_ENTRY(Structure):
    pass
class _HEAP_LOCK(Structure):
    pass
_HEAP._fields_ = [
    ('Segment', _HEAP_SEGMENT),
    ('Flags', __uint32_t),
    ('ForceFlags', __uint32_t),
    ('CompatibilityFlags', __uint32_t),
    ('EncodeFlagMask', __uint32_t),
    ('Encoding', _HEAP_ENTRY),
    ('PointerKey', __uint32_t),
    ('Interceptor', __uint32_t),
    ('VirtualMemoryThreshold', __uint32_t),
    ('Signature', __uint32_t),
    ('SegmentReserve', __uint32_t),
    ('SegmentCommit', __uint32_t),
    ('DeCommitFreeBlockThreshold', __uint32_t),
    ('DeCommitTotalFreeThreshold', __uint32_t),
    ('TotalFreeSize', __uint32_t),
    ('MaximumAllocationSize', __uint32_t),
    ('ProcessHeapsListIndex', __uint16_t),
    ('HeaderValidateLength', __uint16_t),
    ('HeaderValidateCopy', POINTER(VOID)),
    ('NextAvailableTagIndex', __uint16_t),
    ('MaximumTagIndex', __uint16_t),
    ('TagEntries', POINTER(_HEAP_TAG_ENTRY)),
    ('UCRList', _LIST_ENTRY),
    ('AlignRound', __uint32_t),
    ('AlignMask', __uint32_t),
    ('VirtualAllocdBlocks', _LIST_ENTRY),
    ('SegmentList', _LIST_ENTRY),
    ('AllocatorBackTraceIndex', __uint16_t),
    ('_PADDING0_', __uint8_t * 2),
    ('NonDedicatedListLength', __uint32_t),
    ('BlocksIndex', POINTER(VOID)),
    ('UCRIndex', POINTER(VOID)),
    ('PseudoTagEntries', POINTER(_HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', _LIST_ENTRY),
    ('LockVariable', POINTER(_HEAP_LOCK)),
    ('CommitRoutine', POINTER(VOID)),
    ('FrontEndHeap', POINTER(VOID)),
    ('FrontHeapLockCount', __uint16_t),
    ('FrontEndHeapType', __uint8_t),
    ('_PADDING1_', __uint8_t * 1),
    ('Counters', _HEAP_COUNTERS),
    ('TuningParameters', _HEAP_TUNING_PARAMETERS),
]
PHEAP = POINTER(_HEAP)
HEAP = _HEAP
class _HEAP_ENTRY_EXTRA(Structure):
    pass
class N17_HEAP_ENTRY_EXTRA3DOT_6E(Union):
    pass
class N17_HEAP_ENTRY_EXTRA3DOT_63DOT_7E(Structure):
    pass
N17_HEAP_ENTRY_EXTRA3DOT_63DOT_7E._fields_ = [
    ('AllocatorBackTraceIndex', __uint16_t),
    ('TagIndex', __uint16_t),
    ('Settable', __uint32_t),
]
N17_HEAP_ENTRY_EXTRA3DOT_6E._pack_ = 4
N17_HEAP_ENTRY_EXTRA3DOT_6E._anonymous_ = ['_0']
N17_HEAP_ENTRY_EXTRA3DOT_6E._fields_ = [
    ('_0', N17_HEAP_ENTRY_EXTRA3DOT_63DOT_7E),
    ('ZeroInit', __uint64_t),
]
_HEAP_ENTRY_EXTRA._anonymous_ = ['_0']
_HEAP_ENTRY_EXTRA._fields_ = [
    ('_0', N17_HEAP_ENTRY_EXTRA3DOT_6E),
]
HEAP_ENTRY_EXTRA = _HEAP_ENTRY_EXTRA
PHEAP_ENTRY_EXTRA = POINTER(_HEAP_ENTRY_EXTRA)
class _HEAP_FREE_ENTRY(Structure):
    pass
_HEAP_FREE_ENTRY._fields_ = [
    ('Entry', _HEAP_ENTRY),
    ('FreeList', _LIST_ENTRY),
]
PHEAP_FREE_ENTRY = POINTER(_HEAP_FREE_ENTRY)
HEAP_FREE_ENTRY = _HEAP_FREE_ENTRY
class _HEAP_LIST_LOOKUP(Structure):
    pass
_HEAP_LIST_LOOKUP._fields_ = [
    ('ExtendedLookup', POINTER(_HEAP_LIST_LOOKUP)),
    ('ArraySize', __uint32_t),
    ('ExtraItem', __uint32_t),
    ('ItemCount', __uint32_t),
    ('OutOfRangeItems', __uint32_t),
    ('BaseIndex', __uint32_t),
    ('ListHead', POINTER(_LIST_ENTRY)),
    ('ListsInUseUlong', POINTER(__uint32_t)),
    ('ListHints', POINTER(POINTER(_LIST_ENTRY))),
]
PHEAP_LIST_LOOKUP = POINTER(_HEAP_LIST_LOOKUP)
HEAP_LIST_LOOKUP = _HEAP_LIST_LOOKUP
class _HEAP_LOOKASIDE(Structure):
    pass
_HEAP_LOOKASIDE._fields_ = [
    ('ListHead', _SLIST_HEADER),
    ('Depth', __uint16_t),
    ('MaximumDepth', __uint16_t),
    ('TotalAllocates', __uint32_t),
    ('AllocateMisses', __uint32_t),
    ('TotalFrees', __uint32_t),
    ('FreeMisses', __uint32_t),
    ('LastTotalAllocates', __uint32_t),
    ('LastAllocateMisses', __uint32_t),
    ('Counters', __uint32_t * 2),
    ('_PADDING0_', __uint8_t * 4),
]
HEAP_LOOKASIDE = _HEAP_LOOKASIDE
PHEAP_LOOKASIDE = POINTER(_HEAP_LOOKASIDE)
class _INTERLOCK_SEQ(Structure):
    pass
class N14_INTERLOCK_SEQ3DOT_8E(Union):
    pass
class N14_INTERLOCK_SEQ3DOT_83DOT_9E(Structure):
    pass
N14_INTERLOCK_SEQ3DOT_83DOT_9E._fields_ = [
    ('Depth', __uint16_t),
    ('FreeEntryOffset', __uint16_t),
    ('_PADDING0_', __uint8_t * 4),
]
class N14_INTERLOCK_SEQ3DOT_84DOT_10E(Structure):
    pass
N14_INTERLOCK_SEQ3DOT_84DOT_10E._fields_ = [
    ('OffsetAndDepth', __uint32_t),
    ('Sequence', __uint32_t),
]
__int64_t = c_longlong
N14_INTERLOCK_SEQ3DOT_8E._pack_ = 4
N14_INTERLOCK_SEQ3DOT_8E._anonymous_ = ['_0', '_1']
N14_INTERLOCK_SEQ3DOT_8E._fields_ = [
    ('_0', N14_INTERLOCK_SEQ3DOT_83DOT_9E),
    ('_1', N14_INTERLOCK_SEQ3DOT_84DOT_10E),
    ('Exchg', __int64_t),
]
_INTERLOCK_SEQ._anonymous_ = ['_0']
_INTERLOCK_SEQ._fields_ = [
    ('_0', N14_INTERLOCK_SEQ3DOT_8E),
]
INTERLOCK_SEQ = _INTERLOCK_SEQ
PINTERLOCK_SEQ = POINTER(_INTERLOCK_SEQ)
_HEAP_TAG_ENTRY._fields_ = [
    ('Allocs', __uint32_t),
    ('Frees', __uint32_t),
    ('Size', __uint32_t),
    ('TagIndex', __uint16_t),
    ('CreatorBackTraceIndex', __uint16_t),
    ('TagName', __uint16_t * 24),
]
HEAP_TAG_ENTRY = _HEAP_TAG_ENTRY
PHEAP_TAG_ENTRY = POINTER(_HEAP_TAG_ENTRY)
class _HEAP_UCR_DESCRIPTOR(Structure):
    pass
_HEAP_UCR_DESCRIPTOR._fields_ = [
    ('ListEntry', _LIST_ENTRY),
    ('SegmentEntry', _LIST_ENTRY),
    ('Address', POINTER(VOID)),
    ('Size', __uint32_t),
]
HEAP_UCR_DESCRIPTOR = _HEAP_UCR_DESCRIPTOR
PHEAP_UCR_DESCRIPTOR = POINTER(_HEAP_UCR_DESCRIPTOR)
class _HEAP_USERDATA_HEADER(Structure):
    pass
class N21_HEAP_USERDATA_HEADER4DOT_11E(Union):
    pass
class _HEAP_SUBSEGMENT(Structure):
    pass
N21_HEAP_USERDATA_HEADER4DOT_11E._fields_ = [
    ('SFreeListEntry', _SINGLE_LIST_ENTRY),
    ('SubSegment', POINTER(_HEAP_SUBSEGMENT)),
]
_HEAP_USERDATA_HEADER._anonymous_ = ['_0']
_HEAP_USERDATA_HEADER._fields_ = [
    ('_0', N21_HEAP_USERDATA_HEADER4DOT_11E),
    ('Reserved', POINTER(VOID)),
    ('SizeIndex', __uint32_t),
    ('Signature', __uint32_t),
]
HEAP_USERDATA_HEADER = _HEAP_USERDATA_HEADER
PHEAP_USERDATA_HEADER = POINTER(_HEAP_USERDATA_HEADER)
class _HEAP_VIRTUAL_ALLOC_ENTRY(Structure):
    pass
_HEAP_VIRTUAL_ALLOC_ENTRY._fields_ = [
    ('Entry', _LIST_ENTRY),
    ('ExtraStuff', _HEAP_ENTRY_EXTRA),
    ('CommitSize', __uint32_t),
    ('ReserveSize', __uint32_t),
    ('BusyBlock', _HEAP_ENTRY),
]
PHEAP_VIRTUAL_ALLOC_ENTRY = POINTER(_HEAP_VIRTUAL_ALLOC_ENTRY)
HEAP_VIRTUAL_ALLOC_ENTRY = _HEAP_VIRTUAL_ALLOC_ENTRY
class _USER_MEMORY_CACHE_ENTRY(Structure):
    pass
_USER_MEMORY_CACHE_ENTRY._fields_ = [
    ('Foo', __uint32_t * 4),
]
class _HEAP_BUCKET(Structure):
    pass
_HEAP_BUCKET._fields_ = [
    ('Foo', __uint32_t),
]
class _HEAP_BUCKET_COUNTERS(Structure):
    pass
_HEAP_BUCKET_COUNTERS._fields_ = [
    ('Foo', __uint32_t * 2),
]
class _HEAP_LOCAL_SEGMENT_INFO(Structure):
    pass
class _HEAP_LOCAL_DATA(Structure):
    pass
_HEAP_LOCAL_SEGMENT_INFO._fields_ = [
    ('Hint', POINTER(_HEAP_SUBSEGMENT)),
    ('ActiveSubsegment', POINTER(_HEAP_SUBSEGMENT)),
    ('CachedItems', POINTER(_HEAP_SUBSEGMENT) * 16),
    ('SListHeader', _SLIST_HEADER),
    ('Counters', _HEAP_BUCKET_COUNTERS),
    ('LocalData', POINTER(_HEAP_LOCAL_DATA)),
    ('LastOpSequence', __uint32_t),
    ('BucketIndex', __uint16_t),
    ('LastUsed', __uint16_t),
    ('Pad', __uint32_t),
]
HEAP_LOCAL_SEGMENT_INFO = _HEAP_LOCAL_SEGMENT_INFO
PHEAP_LOCAL_SEGMENT_INFO = POINTER(_HEAP_LOCAL_SEGMENT_INFO)
class _LFH_BLOCK_ZONE(Structure):
    pass
class _LFH_HEAP(Structure):
    pass
_HEAP_LOCAL_DATA._fields_ = [
    ('DeletedSubSegments', _SLIST_HEADER),
    ('CrtZone', POINTER(_LFH_BLOCK_ZONE)),
    ('LowFragHeap', POINTER(_LFH_HEAP)),
    ('Sequence', __uint32_t),
    ('SegmentInfo', _HEAP_LOCAL_SEGMENT_INFO * 128),
]
HEAP_LOCAL_DATA = _HEAP_LOCAL_DATA
_HEAP_SUBSEGMENT._fields_ = [
    ('LocalInfo', POINTER(_HEAP_LOCAL_SEGMENT_INFO)),
    ('UserBlocks', POINTER(_HEAP_USERDATA_HEADER)),
    ('AggregateExchg', _INTERLOCK_SEQ),
    ('BlockSize', __uint16_t),
    ('Flags', __uint16_t),
    ('BlockCount', __uint16_t),
    ('SizeIndex', __uint8_t),
    ('AffinityIndex', __uint8_t),
    ('SFreeListEntry', _SINGLE_LIST_ENTRY),
    ('Lock', __uint32_t),
]
HEAP_SUBSEGMENT = _HEAP_SUBSEGMENT
PHEAP_SUBSEGMENT = POINTER(_HEAP_SUBSEGMENT)
_LFH_HEAP._fields_ = [
    ('Lock', __uint32_t * 6),
    ('SubSegmentZones', _LIST_ENTRY),
    ('ZoneBlockSize', __uint32_t),
    ('Heap', POINTER(VOID)),
    ('SegmentChange', __uint32_t),
    ('SegmentCreate', __uint32_t),
    ('SegmentInsertInFree', __uint32_t),
    ('SegmentDelete', __uint32_t),
    ('CacheAllocs', __uint32_t),
    ('CacheFrees', __uint32_t),
    ('SizeInCache', __uint32_t),
    ('RunInfo', __uint32_t * 3),
    ('UserBlockCache', _USER_MEMORY_CACHE_ENTRY * 12),
    ('Buckets', _HEAP_BUCKET * 128),
    ('LocalData', _HEAP_LOCAL_DATA * 1),
]
LFH_HEAP = _LFH_HEAP
__u_char = c_ubyte
__u_short = c_ushort
__u_int = c_uint
__u_long = c_ulong
__int8_t = c_byte
__int16_t = c_short
__int32_t = c_int
__quad_t = c_longlong
__u_quad_t = c_ulonglong
__dev_t = __u_quad_t
__uid_t = c_uint
__gid_t = c_uint
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
__off_t = c_long
__off64_t = __quad_t
__pid_t = c_int
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
__clock_t = c_long
__rlim_t = c_ulong
__rlim64_t = __u_quad_t
__id_t = c_uint
__time_t = c_long
__useconds_t = c_uint
__suseconds_t = c_long
__daddr_t = c_int
__swblk_t = c_long
__key_t = c_int
__clockid_t = c_int
__timer_t = c_void_p
__blksize_t = c_long
__blkcnt_t = c_long
__blkcnt64_t = __quad_t
__fsblkcnt_t = c_ulong
__fsblkcnt64_t = __u_quad_t
__fsfilcnt_t = c_ulong
__fsfilcnt64_t = __u_quad_t
__ssize_t = c_int
__loff_t = __off64_t
__qaddr_t = POINTER(__quad_t)
__caddr_t = STRING
__intptr_t = c_int
__socklen_t = c_uint
__all__ = ['__uint16_t', '__int16_t', 'HEAP_VIRTUAL_ALLOC_ENTRY',
           'VOID', '_HEAP_LOCK', '__fsid_t', '__off64_t',
           'INTERLOCK_SEQ', '__uint32_t', '__timer_t',
           '_HEAP_UCR_DESCRIPTOR', '__rlim64_t',
           'PHEAP_LOCAL_SEGMENT_INFO', '__ino64_t', '__qaddr_t',
           'LFH_HEAP', 'N11_HEAP_ENTRY3DOT_13DOT_3E', '__loff_t',
           'HEAP_ENTRY', '_HEAP_LOOKASIDE', '__time_t',
           '_SLIST_HEADER', 'PINTERLOCK_SEQ', '__int32_t',
           '__nlink_t', 'HEAP_FREE_ENTRY', '__swblk_t',
           'PHEAP_SEGMENT', '__uint64_t', '__ssize_t',
           '_HEAP_VIRTUAL_ALLOC_ENTRY', 'N11_HEAP_ENTRY3DOT_13DOT_5E',
           '_LFH_HEAP', '__id_t', 'HEAP_SUBSEGMENT', 'HEAP_TAG_ENTRY',
           '__clockid_t', '__useconds_t', '_HEAP_TUNING_PARAMETERS',
           'HEAP_USERDATA_HEADER', 'HEAP_LOOKASIDE',
           '_USER_MEMORY_CACHE_ENTRY', '_HEAP_ENTRY',
           'HEAP_LOCAL_DATA', '_SINGLE_LIST_ENTRY',
           '_HEAP_PSEUDO_TAG_ENTRY', 'PHEAP_TUNING_PARAMETERS',
           'PHEAP_TAG_ENTRY', 'SLIST_HEADER',
           '_HEAP_LOCAL_SEGMENT_INFO', '__u_long',
           'N14_INTERLOCK_SEQ3DOT_84DOT_10E',
           'HEAP_LOCAL_SEGMENT_INFO', '__blkcnt_t', 'HEAP_SEGMENT',
           'HEAP_COUNTERS', '_HEAP_BUCKET_COUNTERS', 'PHEAP_ENTRY',
           'HEAP_LIST_LOOKUP', '_HEAP_LIST_LOOKUP',
           '_HEAP_ENTRY_EXTRA', 'N14_INTERLOCK_SEQ3DOT_83DOT_9E',
           '__mode_t', '__blksize_t', 'N14_INTERLOCK_SEQ3DOT_8E',
           '__off_t', '__intptr_t', '__gid_t', '_HEAP_LOCAL_DATA',
           'PSLIST_HEADER', '__daddr_t', 'HEAPTABLE', '__caddr_t',
           '__uint8_t', '_HEAP_SUBSEGMENT', '__u_char',
           '__fsblkcnt64_t', '__blkcnt64_t', '_HEAP_BUCKET',
           'PHEAP_FREE_ENTRY', '_HEAP_FREE_ENTRY', '_HEAP',
           '_HEAP_SEGMENT', 'HEAP_TUNING_PARAMETERS',
           '_INTERLOCK_SEQ', '__suseconds_t', 'HEAP_ENTRY_EXTRA',
           '__fsfilcnt64_t', '__socklen_t',
           'N17_HEAP_ENTRY_EXTRA3DOT_63DOT_7E',
           'N11_HEAP_ENTRY3DOT_1E', '_HEAP_TAG_ENTRY',
           '_LFH_BLOCK_ZONE', 'PHEAP', '_HEAP_USERDATA_HEADER',
           'PHEAP_LIST_LOOKUP', 'PHEAP_SUBSEGMENT', '__fsblkcnt_t',
           '__rlim_t', 'HEAP_UCR_DESCRIPTOR', 'PHEAP_USERDATA_HEADER',
           'PHEAP_LOOKASIDE', 'N11_HEAP_ENTRY3DOT_13DOT_33DOT_4E',
           '__u_quad_t', '__u_short', 'PHEAP_ENTRY_EXTRA', '__pid_t',
           'N21_HEAP_USERDATA_HEADER4DOT_11E', '_HEAP_COUNTERS',
           '__ino_t', 'HEAP', 'PHEAP_VIRTUAL_ALLOC_ENTRY',
           'N17_HEAP_ENTRY_EXTRA3DOT_6E', 'PHEAP_COUNTERS',
           'N11_HEAP_ENTRY3DOT_13DOT_2E', '_LIST_ENTRY',
           '__fsfilcnt_t', 'PHEAP_UCR_DESCRIPTOR', '__u_int',
           '__quad_t', '__int64_t', '__key_t', '__clock_t', '__uid_t',
           '__int8_t', '__dev_t']
