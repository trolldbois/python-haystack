# -*- coding: utf-8 -*-
#
""" Win 7 heap structure - from LGPL metasm.
See docs/win32_heap for all supporting documentation.

The Heap Manager organizes its virtual memory using heap segments.
Distinction between reserved and committed memory.
Committing memory == mapping/backing the virtual memory.
Uncommitted memory is tracked using UCR entries and segments.

heap_size = heap.Counters.TotalMemoryReserved
committed_size = heap.Segment.LastValidEntry -  heap.Segment.FirstEntry
committed_size = heap.Counters.TotalMemoryCommitted
ucr_size= heap.Counters.TotalMemoryReserved - heap.Counters.TotalMemoryCommitted

Win7 Heap manager uses either Frontend allocator or Backend allocator.
Default Frontend allocator is Low Fragmentation Heap (LFH).

Chunks are allocated memory.
List of chunks allocated by the backend allocators are linked in
heap.segment.FirstValidEntry to LastValidEntry.
LFH allocations are in one big chunk of that list at heap.FrontEndHeap.

There can be multiple segment in one heap.
Each segment has a FirstEntry (chunk) and LastValidEntry.
FirstEntry <= chunks <= UCR < LastValidEntry

You can fetch chunks tuple(address,size) with HEAP.get_chunks .

You can fetch ctypes segments with HEAP.get_segment_list
You can fetch free ctypes UCR segments with HEAP.get_UCR_segment_list
You can fetch a segment UCR segments with HEAP_SEGMENT.get_UCR_segment_list

"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

"""ensure ctypes basic types are subverted"""

import ctypes
import logging

from haystack import model
from haystack.abc import interfaces
from haystack.structures.win32 import winheap



# pylint: disable=pointeless-string-statement
'''
# Critical structs are
_LIST_ENTRY
_LFH_BLOCK_ZONE
_HEAP_PSEUDO_TAG_ENTRY
_HEAP_LOCK
_HEAPTABLE
_SLIST_HEADER
_SINGLE_LIST_ENTRY
_HEAP_ENTRY
_HEAP_COUNTERS
_HEAP_TUNING_PARAMETERS
_HEAP_SEGMENT
_HEAP
_HEAP_ENTRY_EXTRA
_HEAP_FREE_ENTRY
_HEAP_LIST_LOOKUP
_HEAP_LOOKASIDE
_INTERLOCK_SEQ
_HEAP_TAG_ENTRY
_HEAP_UCR_DESCRIPTOR
_HEAP_USERDATA_HEADER
_HEAP_VIRTUAL_ALLOC_ENTRY
_HEAP_LOCAL_SEGMENT_INFO
_HEAP_LOCAL_DATA
_HEAP_SUBSEGMENT
_LFH_HEAP
'''

log = logging.getLogger('win7heap')

############# Start methods overrides #################
# constraints are in constraints files

class Win7HeapValidator(winheap.WinHeapValidator):
    """
    this listmodel Validator will register know important list fields
    in the win7 HEAP,
    [ FIXME TODO and apply constraints ? ]
    and be used to validate the loading of these structures.
    This class contains all helper functions used to parse the win7heap structures.
    """

    def __init__(self, memory_handler, my_constraints, win7heap_module):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        super(Win7HeapValidator, self).__init__(memory_handler, my_constraints)
        self.win_heap = win7heap_module
        # LIST_ENTRY
        # the lists usually use end of mapping as a sentinel.
        # we have to use all mappings instead of heaps, because of a circular dependency
        sentinels = [mapping.end-0x10 for mapping in self._memory_handler.get_mappings()]
        self.register_double_linked_list_record_type(self.win_heap.LIST_ENTRY, 'Flink', 'Blink', sentinels)

        # HEAP_SEGMENT
        # HEAP_SEGMENT.UCRSegmentList. points to HEAP_UCR_DESCRIPTOR.SegmentEntry.
        # HEAP_UCR_DESCRIPTOR.SegmentEntry. points to HEAP_SEGMENT.UCRSegmentList.
        # FIXME, use offset size base on self._target.get_word_size()
        self.register_linked_list_field_and_type(self.win_heap.HEAP_SEGMENT, 'UCRSegmentList', self.win_heap.HEAP_UCR_DESCRIPTOR, 'ListEntry') # offset = -8
        #HEAP_SEGMENT._listHead_ = [
        #        ('UCRSegmentList', HEAP_UCR_DESCRIPTOR, 'ListEntry', -8)]
        #HEAP_UCR_DESCRIPTOR._listHead_ = [ ('SegmentEntry', HEAP_SEGMENT, 'Entry')]

        # HEAP CommitRoutine encoded by a global key
        # The HEAP handle data structure includes a function pointer field called
        # CommitRoutine that is called when memory regions within the heap are committed.
        # Starting with Windows Vista, this field was encoded using a random value that
        # was also stored as a field in the HEAP handle data structure.

        #HEAP._listHead_ = [('SegmentList', HEAP_SEGMENT, 'SegmentListEntry', -16),
        #                   ('UCRList', HEAP_UCR_DESCRIPTOR, 'ListEntry', 0),
        #                   # for get_freelists. offset is sizeof(HEAP_ENTRY)
        #                   ('FreeLists', HEAP_FREE_ENTRY, 'FreeList', -8),
        #                   ('VirtualAllocdBlocks', HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8)]
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'SegmentList', self.win_heap.HEAP_SEGMENT, 'SegmentListEntry') # offset = -16
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'UCRList', self.win_heap.HEAP_UCR_DESCRIPTOR, 'ListEntry') # offset = 0
        # for get_freelists. offset is sizeof(HEAP_ENTRY)
        ## self.register_linked_list_field_and_type(self.win_heap.HEAP, 'FreeLists', self.win_heap.HEAP_FREE_ENTRY, 'FreeList') # offset =  -8
        if self._target.get_word_size() == 4:
            self.register_linked_list_field_and_type(self.win_heap.HEAP, 'FreeLists', self.win_heap.struct__HEAP_FREE_ENTRY_0_5, 'FreeList') # offset =  -8
        else:
            self.register_linked_list_field_and_type(self.win_heap.HEAP, 'FreeLists', self.win_heap.struct__HEAP_FREE_ENTRY_0_2, 'FreeList') # offset =  -8
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'VirtualAllocdBlocks', self.win_heap.HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry') # offset = -8

        # HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
        # SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
        # you need to ignore the Head in the iterator...

        # HEAP_UCR_DESCRIPTOR
        #HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
        #HEAP_UCR_DESCRIPTOR._listHead_ = [    ('SegmentEntry', HEAP_SEGMENT, 'SegmentListEntry'),    ]

    def HEAP_get_segment_list(self, record):
        """returns a list of all segment attached to one Heap structure."""
        segments = list()
        for segment in self.iterate_list_from_field(record, 'SegmentList'):
            segment_addr = segment._orig_address_
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            log.debug(
                'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x' %
                (segment_addr, first_addr, last_addr))
            segments.append(segment)
        return segments

