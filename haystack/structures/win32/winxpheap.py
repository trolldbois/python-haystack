# -*- coding: utf-8 -*-
#


""" Win heap structure - from LGPL metasm
http://www.informit.com/articles/article.aspx?p=1081496

"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

import ctypes
import logging

from haystack.abc import interfaces
from haystack import model
from haystack import utils
from haystack.structures.win32 import winheap

log = logging.getLogger('winxpheap')

# constraints are in constraints files

class WinXPHeapValidator(winheap.WinHeapValidator):
    """
    this listmodel Validator will register know important list fields
    in the winxp HEAP,
    and be used to validate the loading of these structures.
    This class contains all helper functions used to parse the winxpheap structures.
    """

    def __init__(self, memory_handler, my_constraints, winxpheap_module):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        super(WinXPHeapValidator, self).__init__(memory_handler, my_constraints)
        self.win_heap = winxpheap_module
        # TODO 2015-06 check, I thing segmentlist where 'segments' array in xp
        '''HEAP._listHead_ = [#('SegmentList', HEAP_SEGMENT, 'SegmentListEntry', -16),
                           # maybe UCRsegments ???
                           #('UCRList', HEAP_UCR_DESCRIPTOR, 'ListEntry', 0),
                           # for get_freelists. offset is sizeof(HEAP_ENTRY)
                           #('FreeLists', HEAP_FREE_ENTRY, 'FreeList', -8),
                           ('VirtualAllocdBlocks', HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8)]
        '''
        # HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
        # SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
        # you need to ignore the Head in the iterator...

        # LIST_ENTRY
        # the lists usually use end of mapping as a sentinel.
        # we have to use all mappings instead of heaps, because of a circular dependency
        sentinels = [mapping.end-0x10 for mapping in self._memory_handler.get_mappings()]
        sentinels.append(0xffffffff)
        self.register_double_linked_list_record_type(self.win_heap.struct__LIST_ENTRY, 'Flink', 'Blink', sentinels)
        #
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'VirtualAllocdBlocks', self.win_heap.HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry') # offset = -8

        # we need a single linked pointer list management

        #class struct__HEAP_LOOKASIDE(ctypes.Structure):
        #    ('ListHead', SLIST_HEADER),

        #SLIST_HEADER = union__SLIST_HEADER

        #class union__SLIST_HEADER(ctypes.Union):
        #    ('Alignment', ctypes.c_uint64),
        #    ('_1', struct__SLIST_HEADER_0),

        #class struct__SLIST_HEADER_0(ctypes.Structure):
        #    ('Next', SINGLE_LIST_ENTRY),
        self.register_single_linked_list_record_type(self.win_heap.struct__SINGLE_LIST_ENTRY, 'Next')
        self.register_linked_list_field_and_type(self.win_heap.struct__HEAP_LOOKASIDE, 'ListHead', self.win_heap.struct__SINGLE_LIST_ENTRY, 'Next')

        return

    # 2015-06-30 modified for windows xp
    #('Segments', POINTER_T(struct__HEAP_SEGMENT) * 64),
    def HEAP_get_segment_list(self, record):
        """returns a list of all segment attached to one Heap structure."""
        segments = list()
        segments_addr = self._utils.get_pointee_address(record.Segments)
        if segments_addr == 0:
            return []
        m = self._memory_handler.get_mapping_for_address(segments_addr)
        if not m:
            raise RuntimeError('HEAP.Segments has a bad address %x' % segments_addr)
        st = m.read_struct(segments_addr, (self.win_heap.struct__HEAP_SEGMENT*64))
        base_addr = st._orig_address_
        size_segment = ctypes.sizeof(self.win_heap.struct__HEAP_SEGMENT)
        for i, segment in enumerate(st):
            segment_addr = segment._orig_address_+(i*size_segment)
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            log.debug(
                'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x' %
                (segment_addr, first_addr, last_addr))
            segments.append(segment)
        return segments

    # 2015-06-30 for winXP
    #     ('FreeLists', struct__LIST_ENTRY * 128),
    def HEAP_get_freelists(self, mappings):
        """Returns the list of free chunks.

        This method is very important because its used by memory_mappings to
        load _memory_handler that contains subsegment of a heap.

        Understanding_the_LFH.pdf page 18 ++
        We iterate on HEAP.FreeLists to get ALL free blocks.

        @returns freeblock_addr : the address of the HEAP_ENTRY (chunk header)
            size : the size of the free chunk + HEAP_ENTRY header size, in blocks.
        """
        # FIXME: we should use get_segmentlist to coallescce segment in one heap
        # memory mapping. Not free chunks.
        res = list()
        # todo iterate on the 128 list_entry, which are pointing to HEAP_ENTRY
        # FIXME
        return res




# HEAP_UCR_DESCRIPTOR
#HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
#HEAP_UCR_DESCRIPTOR._listHead_ = [    ('SegmentEntry', HEAP_SEGMENT, 'SegmentListEntry'),    ]

# per definition, reserved space is not maped.
#HEAP_UCR_DESCRIPTOR.expectedValues = {
#    'Address': constraints.IgnoreMember,
#}

# HEAP_LOCAL_SEGMENT_INFO
# HEAP_LOCAL_SEGMENT_INFO.LocalData should be a pointer, but the values are small ints ?
# HEAP_LOCAL_SEGMENT_INFO.LocalData == 0x3 ?
#HEAP_LOCAL_SEGMENT_INFO.expectedValues = {
#    'LocalData': constraints.IgnoreMember,
#}

