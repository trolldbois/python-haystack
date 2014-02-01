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
class _SLIST_HEADER(Union):
    pass
_SLIST_HEADER._fields_ = [
    ('le', _LIST_ENTRY),
]
class _HEAP_ENTRY(Structure):
    pass
__uint16_t = c_ushort
__uint8_t = c_ubyte
_HEAP_ENTRY._fields_ = [
    ('Size', __uint16_t),
    ('PreviousSize', __uint16_t),
    ('SmallTagIndex', __uint8_t),
    ('Flags', __uint8_t),
    ('UnusedBytes', __uint8_t),
    ('SegmentIndex', __uint8_t),
]
PHEAP_ENTRY = POINTER(_HEAP_ENTRY)
HEAP_ENTRY = _HEAP_ENTRY
__uint32_t = c_uint
class _HEAP_TAG_ENTRY(Structure):
    pass
class _HEAP_UCR_SEGMENT(Structure):
    pass
class _HEAP_UNCOMMMTTED_RANGE(Structure):
    pass
class _HEAP_SEGMENT(Structure):
    pass
class N5_HEAP3DOT_1E(Union):
    pass
N5_HEAP3DOT_1E._fields_ = [
    ('FreeListsInUseUlong', __uint32_t * 4),
    ('FreeListsInUseBytes', __uint8_t * 16),
]
class N5_HEAP3DOT_2E(Union):
    pass
N5_HEAP3DOT_2E._fields_ = [
    ('FreeListsInUseTerminate', __uint16_t),
    ('DecommitCount', __uint16_t),
]
class _HEAP_PSEUDO_TAG_ENTRY(Structure):
    pass
class _HEAP_LOCK(Structure):
    pass
_HEAP._fields_ = [
    ('Entry', _HEAP_ENTRY),
    ('Signature', __uint32_t),
    ('Flags', __uint32_t),
    ('ForceFlags', __uint32_t),
    ('VirtualMemoryThreshold', __uint32_t),
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
    ('UCRSegments', POINTER(_HEAP_UCR_SEGMENT)),
    ('UnusedUnCommittedRanges', POINTER(_HEAP_UNCOMMMTTED_RANGE)),
    ('AlignRound', __uint32_t),
    ('AlignMask', __uint32_t),
    ('VirtualAllocdBlocks', _LIST_ENTRY),
    ('Segments', POINTER(_HEAP_SEGMENT) * 64),
    ('u', N5_HEAP3DOT_1E),
    ('u2', N5_HEAP3DOT_2E),
    ('AllocatorBackTraceIndex', __uint16_t),
    ('NonDedicatedListLength', __uint32_t),
    ('LargeBlocksIndex', POINTER(VOID)),
    ('PseudoTagEntries', POINTER(_HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', _LIST_ENTRY * 128),
    ('LockVariable', POINTER(_HEAP_LOCK)),
    ('CommitRoutine', POINTER(VOID)),
    ('FrontEndHeap', POINTER(VOID)),
    ('FrontHeapLockCount', __uint16_t),
    ('FrontEndHeapType', __uint8_t),
    ('LastSegmentIndex', __uint8_t),
]
PHEAP = POINTER(_HEAP)
HEAP = _HEAP
_HEAP_UNCOMMMTTED_RANGE._fields_ = [
    ('Next', POINTER(_HEAP_UNCOMMMTTED_RANGE)),
    ('Address', __uint32_t),
    ('Size', __uint32_t),
    ('filler', __uint32_t),
]
HEAP_UNCOMMMTTED_RANGE = _HEAP_UNCOMMMTTED_RANGE
PHEAP_UNCOMMMTTED_RANGE = POINTER(_HEAP_UNCOMMMTTED_RANGE)
class _HEAP_ENTRY_EXTRA(Structure):
    pass
class N17_HEAP_ENTRY_EXTRA3DOT_3E(Union):
    pass
class N17_HEAP_ENTRY_EXTRA3DOT_33DOT_4E(Structure):
    pass
N17_HEAP_ENTRY_EXTRA3DOT_33DOT_4E._fields_ = [
    ('AllocatorBackTraceIndex', __uint16_t),
    ('TagIndex', __uint16_t),
    ('Settable', __uint32_t),
]
__uint64_t = c_ulonglong
N17_HEAP_ENTRY_EXTRA3DOT_3E._pack_ = 4
N17_HEAP_ENTRY_EXTRA3DOT_3E._anonymous_ = ['_0']
N17_HEAP_ENTRY_EXTRA3DOT_3E._fields_ = [
    ('_0', N17_HEAP_ENTRY_EXTRA3DOT_33DOT_4E),
    ('ZeroInit', __uint64_t),
]
_HEAP_ENTRY_EXTRA._anonymous_ = ['_0']
_HEAP_ENTRY_EXTRA._fields_ = [
    ('_0', N17_HEAP_ENTRY_EXTRA3DOT_3E),
]
PHEAP_ENTRY_EXTRA = POINTER(_HEAP_ENTRY_EXTRA)
HEAP_ENTRY_EXTRA = _HEAP_ENTRY_EXTRA
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
class _HEAP_FREE_ENTRY(Structure):
    pass
class N16_HEAP_FREE_ENTRY3DOT_5E(Union):
    pass
class N16_HEAP_FREE_ENTRY3DOT_53DOT_6E(Structure):
    pass
N16_HEAP_FREE_ENTRY3DOT_53DOT_6E._fields_ = [
    ('Size', __uint16_t),
    ('PreviousSize', __uint16_t),
]
N16_HEAP_FREE_ENTRY3DOT_5E._anonymous_ = ['_0']
N16_HEAP_FREE_ENTRY3DOT_5E._fields_ = [
    ('_0', N16_HEAP_FREE_ENTRY3DOT_53DOT_6E),
    ('SubSegmentCode', POINTER(VOID)),
]
_HEAP_FREE_ENTRY._anonymous_ = ['_0']
_HEAP_FREE_ENTRY._fields_ = [
    ('_0', N16_HEAP_FREE_ENTRY3DOT_5E),
    ('SmallTagIndex', __uint8_t),
    ('Flags', __uint8_t),
    ('UnusedBytes', __uint8_t),
    ('SegmentIndex', __uint8_t),
    ('FreeList', _LIST_ENTRY),
]
PHEAP_FREE_ENTRY = POINTER(_HEAP_FREE_ENTRY)
HEAP_FREE_ENTRY = _HEAP_FREE_ENTRY
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
class FRONTEND1(Structure):
    pass
FRONTEND1._fields_ = [
    ('l', _HEAP_LOOKASIDE * 128),
]
_HEAP_SEGMENT._fields_ = [
    ('Entry', _HEAP_ENTRY),
    ('Signature', __uint32_t),
    ('Flags', __uint32_t),
    ('Heap', POINTER(_HEAP)),
    ('LargestUnCommittedRange', __uint32_t),
    ('BaseAddress', POINTER(VOID)),
    ('NumberOfPages', __uint32_t),
    ('FirstEntry', POINTER(_HEAP_ENTRY)),
    ('LastValidEntry', POINTER(_HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', __uint32_t),
    ('NumberOfUnCommittedRanges', __uint32_t),
    ('UnCommittedRanges', POINTER(_HEAP_UNCOMMMTTED_RANGE)),
    ('AllocatorBackTraceIndex', __uint16_t),
    ('Reserved', __uint16_t),
    ('LastEntryInSegment', POINTER(_HEAP_ENTRY)),
]
PHEAP_SEGMENT = POINTER(_HEAP_SEGMENT)
HEAP_SEGMENT = _HEAP_SEGMENT
__u_char = c_ubyte
__u_short = c_ushort
__u_int = c_uint
__u_long = c_ulong
__int8_t = c_byte
__int16_t = c_short
__int32_t = c_int
__int64_t = c_longlong
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
           'N5_HEAP3DOT_2E', '_HEAP_UCR_SEGMENT', '__uint32_t',
           'FRONTEND1', '__ino64_t', '__qaddr_t',
           'N17_HEAP_ENTRY_EXTRA3DOT_33DOT_4E', '__loff_t',
           'HEAP_ENTRY', '_HEAP_LOOKASIDE', '__time_t',
           '_SLIST_HEADER', '__int32_t', '__nlink_t',
           'HEAP_FREE_ENTRY', '__timer_t', 'PHEAP_SEGMENT',
           '__uint64_t', '__ssize_t', '_HEAP_VIRTUAL_ALLOC_ENTRY',
           '__id_t', '__clockid_t', '__useconds_t', 'HEAP_LOOKASIDE',
           '_HEAP_ENTRY', '_HEAP_PSEUDO_TAG_ENTRY', '__intptr_t',
           '__u_long', 'N17_HEAP_ENTRY_EXTRA3DOT_3E',
           'N16_HEAP_FREE_ENTRY3DOT_53DOT_6E', '__blkcnt_t',
           'HEAP_SEGMENT', '_HEAP_UNCOMMMTTED_RANGE', '__rlim64_t',
           'PHEAP_ENTRY', '_HEAP_ENTRY_EXTRA', '__mode_t',
           '__blksize_t', '__off_t', '__gid_t', '__daddr_t',
           'HEAPTABLE', '__caddr_t', 'PHEAP_UNCOMMMTTED_RANGE',
           '__uint8_t', '__u_char', '__fsblkcnt64_t', '__blkcnt64_t',
           '__dev_t', 'PHEAP_FREE_ENTRY', '_HEAP_FREE_ENTRY', '_HEAP',
           '_HEAP_SEGMENT', '__suseconds_t', 'HEAP_UNCOMMMTTED_RANGE',
           'HEAP_ENTRY_EXTRA', '__fsfilcnt64_t', '__int8_t',
           '_HEAP_TAG_ENTRY', 'PHEAP', 'N16_HEAP_FREE_ENTRY3DOT_5E',
           '__fsblkcnt_t', '__rlim_t', 'PHEAP_LOOKASIDE',
           '__u_quad_t', '__u_short', 'PHEAP_ENTRY_EXTRA', '__pid_t',
           'N5_HEAP3DOT_1E', '__ino_t', 'HEAP',
           'PHEAP_VIRTUAL_ALLOC_ENTRY', '__swblk_t', '_LIST_ENTRY',
           '__socklen_t', '__u_int', '__quad_t', '__int64_t',
           '__key_t', '__clock_t', '__uid_t', '__fsfilcnt_t']
