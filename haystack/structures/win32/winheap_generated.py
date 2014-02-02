# -*- coding: utf-8 -*-
#
# TARGET arch is: ['-target', 'i386-win32']
# WORD_SIZE is: 4
# POINTER_SIZE is: 4
# LONGDOUBLE_SIZE is: 8
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

HEAP_TAG_ENTRY = struct__HEAP_TAG_ENTRY

PHEAP_TAG_ENTRY = ctypes.POINTER(struct__HEAP_TAG_ENTRY)

class struct__HEAP_UCR_SEGMENT(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ListEntry', struct__LIST_ENTRY),
    ('ReservedSize', ctypes.c_uint32),
    ('CommittedSize', ctypes.c_uint32),
     ]

PHEAP_UCR_SEGMENT = ctypes.POINTER(struct__HEAP_UCR_SEGMENT)

HEAP_UCR_SEGMENT = struct__HEAP_UCR_SEGMENT

class struct__HEAP_PSEUDO_TAG_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Allocs', ctypes.c_uint32),
    ('Frees', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
     ]

HEAP_PSEUDO_TAG_ENTRY = struct__HEAP_PSEUDO_TAG_ENTRY

PHEAP_PSEUDO_TAG_ENTRY = ctypes.POINTER(struct__HEAP_PSEUDO_TAG_ENTRY)

class struct__HEAP_LOCK(ctypes.Structure):
    pass

class struct_HEAPTABLE(ctypes.Structure):
    pass

class struct__HEAP(ctypes.Structure):
    pass

class struct__HEAP_UNCOMMMTTED_RANGE(ctypes.Structure):
    pass

struct__HEAP_UNCOMMMTTED_RANGE._pack_ = True # source:False
struct__HEAP_UNCOMMMTTED_RANGE._fields_ = [
    ('Next', ctypes.POINTER(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('Address', ctypes.c_uint32),
    ('Size', ctypes.c_uint32),
    ('filler', ctypes.c_uint32),
]

class union_c__S__HEAP_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('FreeListsInUseUlong', ctypes.c_uint32 * 4),
    ('FreeListsInUseBytes', ctypes.c_ubyte * 16),
     ]

class struct__HEAP_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('PreviousSize', ctypes.c_uint16),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('UnusedBytes', ctypes.c_ubyte),
    ('SegmentIndex', ctypes.c_ubyte),
     ]

class struct__HEAP_SEGMENT(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Entry', struct__HEAP_ENTRY),
    ('Signature', ctypes.c_uint32),
    ('Flags', ctypes.c_uint32),
    ('Heap', ctypes.POINTER(struct__HEAP)),
    ('LargestUnCommittedRange', ctypes.c_uint32),
    ('BaseAddress', ctypes.POINTER(None)),
    ('NumberOfPages', ctypes.c_uint32),
    ('FirstEntry', ctypes.POINTER(struct__HEAP_ENTRY)),
    ('LastValidEntry', ctypes.POINTER(struct__HEAP_ENTRY)),
    ('NumberOfUnCommittedPages', ctypes.c_uint32),
    ('NumberOfUnCommittedRanges', ctypes.c_uint32),
    ('UnCommittedRanges', ctypes.POINTER(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('Reserved', ctypes.c_uint16),
    ('LastEntryInSegment', ctypes.POINTER(struct__HEAP_ENTRY)),
     ]

struct__HEAP._pack_ = True # source:False
struct__HEAP._fields_ = [
    ('Entry', struct__HEAP_ENTRY),
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
    ('HeaderValidateCopy', ctypes.POINTER(None)),
    ('NextAvailableTagIndex', ctypes.c_uint16),
    ('MaximumTagIndex', ctypes.c_uint16),
    ('TagEntries', ctypes.POINTER(struct__HEAP_TAG_ENTRY)),
    ('UCRSegments', ctypes.POINTER(struct__HEAP_UCR_SEGMENT)),
    ('UnusedUnCommittedRanges', ctypes.POINTER(struct__HEAP_UNCOMMMTTED_RANGE)),
    ('AlignRound', ctypes.c_uint32),
    ('AlignMask', ctypes.c_uint32),
    ('VirtualAllocdBlocks', struct__LIST_ENTRY),
    ('Segments', ctypes.POINTER(struct__HEAP_SEGMENT) * 64),
    ('u', union_c__S__HEAP_Ua),
    ('u2', union_c__S__HEAP_Ua),
    ('AllocatorBackTraceIndex', ctypes.c_uint16),
    ('NonDedicatedListLength', ctypes.c_uint32),
    ('LargeBlocksIndex', ctypes.POINTER(None)),
    ('PseudoTagEntries', ctypes.POINTER(struct__HEAP_PSEUDO_TAG_ENTRY)),
    ('FreeLists', struct__LIST_ENTRY * 128),
    ('LockVariable', ctypes.POINTER(struct__HEAP_LOCK)),
    ('CommitRoutine', ctypes.POINTER(None)),
    ('FrontEndHeap', ctypes.POINTER(None)),
    ('FrontHeapLockCount', ctypes.c_uint16),
    ('FrontEndHeapType', ctypes.c_ubyte),
    ('LastSegmentIndex', ctypes.c_ubyte),
]

struct_HEAPTABLE._pack_ = True # source:False
struct_HEAPTABLE._fields_ = [
    ('list', ctypes.POINTER(struct__HEAP) * 16),
]

class union__SLIST_HEADER(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('le', struct__LIST_ENTRY),
     ]

PHEAP_ENTRY = ctypes.POINTER(struct__HEAP_ENTRY)

HEAP_ENTRY = struct__HEAP_ENTRY

HEAP = struct__HEAP

PHEAP = ctypes.POINTER(struct__HEAP)

PHEAP_UNCOMMMTTED_RANGE = ctypes.POINTER(struct__HEAP_UNCOMMMTTED_RANGE)

HEAP_UNCOMMMTTED_RANGE = struct__HEAP_UNCOMMMTTED_RANGE

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

HEAP_ENTRY_EXTRA = struct__HEAP_ENTRY_EXTRA

PHEAP_ENTRY_EXTRA = ctypes.POINTER(struct__HEAP_ENTRY_EXTRA)

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

class struct__HEAP_FREE_ENTRY(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('SmallTagIndex', ctypes.c_ubyte),
    ('Flags', ctypes.c_ubyte),
    ('UnusedBytes', ctypes.c_ubyte),
    ('SegmentIndex', ctypes.c_ubyte),
    ('FreeList', struct__LIST_ENTRY),
     ]

class union_c__S__HEAP_FREE_ENTRY_Ua(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('SubSegmentCode', ctypes.POINTER(None)),
     ]

class struct_c__S__HEAP_FREE_ENTRY_Ua_Sa(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('Size', ctypes.c_uint16),
    ('PreviousSize', ctypes.c_uint16),
     ]

PHEAP_FREE_ENTRY = ctypes.POINTER(struct__HEAP_FREE_ENTRY)

HEAP_FREE_ENTRY = struct__HEAP_FREE_ENTRY

class struct__HEAP_LOOKASIDE(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ListHead', union__SLIST_HEADER),
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

class struct_FRONTEND1(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('l', struct__HEAP_LOOKASIDE * 128),
     ]

PHEAP_SEGMENT = ctypes.POINTER(struct__HEAP_SEGMENT)

HEAP_SEGMENT = struct__HEAP_SEGMENT

__all__ = ['PHEAP_SEGMENT', 'PHEAP_FREE_ENTRY', 'PHEAP',
           'HEAP_ENTRY_EXTRA', 'VOID',
           'union_c__S__HEAP_FREE_ENTRY_Ua', 'PHEAP_LOOKASIDE',
           'HEAP_TAG_ENTRY', 'PHEAP_PSEUDO_TAG_ENTRY',
           'HEAP_UCR_SEGMENT', 'union_c__S__HEAP_ENTRY_EXTRA_Ua',
           'HEAP_LOOKASIDE', 'struct__HEAP_ENTRY_EXTRA',
           'struct__HEAP_LOCK', 'HEAP_VIRTUAL_ALLOC_ENTRY',
           'PHEAP_UNCOMMMTTED_RANGE', 'PHEAP_ENTRY_EXTRA',
           'struct__HEAP_VIRTUAL_ALLOC_ENTRY', 'PHEAP_UCR_SEGMENT',
           'struct__HEAP_LOOKASIDE', 'HEAP_ENTRY',
           'struct__HEAP_FREE_ENTRY', 'struct__HEAP_SEGMENT',
           'PHEAP_TAG_ENTRY', 'union__SLIST_HEADER', 'HEAP',
           'PHEAP_VIRTUAL_ALLOC_ENTRY', 'HEAP_SEGMENT',
           'struct__LIST_ENTRY', 'union_c__S__HEAP_Ua',
           'struct_FRONTEND1', 'struct__HEAP_PSEUDO_TAG_ENTRY',
           'struct__HEAP_TAG_ENTRY', 'HEAP_UNCOMMMTTED_RANGE',
           'struct__HEAP', 'struct_HEAPTABLE',
           'struct_c__S__HEAP_ENTRY_EXTRA_Ua_Sa',
           'struct_c__S__HEAP_FREE_ENTRY_Ua_Sa',
           'HEAP_PSEUDO_TAG_ENTRY', 'struct__HEAP_UNCOMMMTTED_RANGE',
           'struct__HEAP_ENTRY', 'HEAP_FREE_ENTRY',
           'struct__HEAP_UCR_SEGMENT', 'PHEAP_ENTRY']
