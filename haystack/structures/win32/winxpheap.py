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

    def p(self, ss):
        # FIXME DEBUG
        from haystack.outputters import text
        parser = text.RecursiveTextOutputter(self._memory_handler)
        return parser.parse(ss)

    def __init__(self, memory_handler, my_constraints, winxpheap_module):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        super(WinXPHeapValidator, self).__init__(memory_handler, my_constraints)
        self.win_heap = winxpheap_module
        '''HEAP._listHead_ =
                           # maybe UCRsegments ???
                           #('UCRList', HEAP_UCR_DESCRIPTOR, 'ListEntry', 0),
                           # for get_freelists. offset is sizeof(HEAP_ENTRY)
                           #('FreeLists', HEAP_FREE_ENTRY, 'FreeList', -8),
                           ('VirtualAllocdBlocks', HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8)]
        '''
        # LIST_ENTRY
        # the lists usually use end of mapping as a sentinel.
        # we have to use all mappings instead of heaps, because of a circular dependency
        # FIXME, type definition should probably not contain sentinels.
        sentinels = [mapping.end-0x10 for mapping in self._memory_handler.get_mappings()]
        sentinels.append(0xffffffff)

        self.register_double_linked_list_record_type(self.win_heap.struct__LIST_ENTRY, 'Flink', 'Blink', sentinels)
        #
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'VirtualAllocdBlocks', self.win_heap.struct__HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry') # offset = -8

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
        #self.register_linked_list_field_and_type(self.win_heap.struct__HEAP_LOOKASIDE, 'ListHead', self.win_heap.struct__SINGLE_LIST_ENTRY, 'Next')
        #self.register_single_linked_list_record_type(self.win_heap.union__SLIST_HEADER, '_1')
        #self.register_single_linked_list_record_type(self.win_heap.struct__SLIST_HEADER_0, 'Next')
        #self.register_linked_list_field_and_type(self.win_heap.struct__HEAP_LOOKASIDE, 'ListHead', self.win_heap.union__SLIST_HEADER, '_1')
        #self.register_linked_list_field_and_type(self.win_heap.union__SLIST_HEADER, '_1', self.win_heap.struct__SLIST_HEADER_0, 'Next')
        self.register_linked_list_field_and_type(self.win_heap.struct__SLIST_HEADER_0, 'Next', self.win_heap.struct__HEAP_LOOKASIDE, 'ListHead')
        # what the fuck is pointed record type of listHead ?
        #self.register_linked_list_field_and_type(self.win_heap.struct__SINGLE_LIST_ENTRY, 'Next', self.win_heap.struct__SINGLE_LIST_ENTRY, 'Next')

        self.register_single_linked_list_record_type(self.win_heap.struct__HEAP_UCR_SEGMENT, 'Next')
        self.register_linked_list_field_and_type(self.win_heap.struct__HEAP_UCR_SEGMENT, 'Next', self.win_heap.struct__HEAP_UCR_SEGMENT, 'Next')

        return

    # 2015-06-30 modified for windows xp
    #('Segments', POINTER_T(struct__HEAP_SEGMENT) * 64),
    def HEAP_get_segment_list(self, record):
        """returns a list of all segment attached to one Heap structure."""
        segments = list()
        # record.segments is a list of 64 struct__HEAP_SEGMENT pointers
        # base_segments_addr = record._orig_address_ + self._utils.offsetof(type(record), 'Segments')
        for i, segment_ptr in enumerate(record.Segments):
            segment_addr = self._utils.get_pointee_address(segment_ptr)
            if segment_addr == 0:
                # FIXME, could some null segments pointer be in the middle ?
                continue
                # return segments
            m = self._memory_handler.get_mapping_for_address(segment_addr)
            if not m:
                raise RuntimeError('HEAP.Segments[%d] has a bad address %x' % (i, segment_addr))
            segment = m.read_struct(segment_addr, self.win_heap.struct__HEAP_SEGMENT)
            # size_segment = ctypes.sizeof(self.win_heap.struct__HEAP_SEGMENT)
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            log.debug(
                    'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x' %
                    (segment_addr, first_addr, last_addr))
            segments.append(segment)
        return segments

    # 2015-06-30 for winXP
    #     ('FreeLists', struct__LIST_ENTRY * 128),
    def HEAP_get_freelists(self, record):
        """Returns the list of free chunks.

        This method is very important because its used by memory_memory_handler to
        load _memory_handler that contains subsegment of a heap.

        Understanding_the_LFH.pdf page 18 ++
        We iterate on HEAP.FreeLists to get ALL free blocks.

        @returns (addr, size)
            freeblock_addr : the address of the HEAP_ENTRY (chunk header)
            size : the size of the free chunk + HEAP_ENTRY header size, in blocks.
        """
        assert isinstance(record, self.win_heap.HEAP)
        # FIXME: we should use get_segmentlist to coallescce segment in one heap
        # memory mapping. Not free chunks.
        res = list()
        # ('FreeLists', struct__LIST_ENTRY * 128),
        # each one of the 128 list is a double linked list of struct__HEAP_ENTRY
        #
        for i, freelist in enumerate(record.FreeLists):
            # FIXME TU: all freeblocks in this list have the same size
            log.debug('HEAP.FreeLists[%d]:', i)
            # AWD: It is critical to note that the pointer listed in the free lists actually points
            # to the user-accessible part of the heap block and not to the start of the heap block
            # itself. As such, if you want to look at the allocation metadata, you need to first
            # subtract 2x wordsize bytes from the pointer.
            #
            # LXJ: hence, the heap entry contains the LIST_ENTRY pointers in the user allocation part.
            # fieldname, pointee_record_type, lefn, offset = link_info
            #
            # we use an internal function to handle that.
            iterator_fn = self._iterate_double_linked_list
            # size is actually a factor of heap granularity == sizeof(HEAP_ENTRY)
            size_heap_entry = self._ctypes.sizeof(self.win_heap.struct__HEAP_ENTRY)
            offset = size_heap_entry
            # the heap.freelists address
            freelists_addr = record._orig_address_ + self._utils.offsetof(type(record), 'FreeLists')
            # every list head is a sentinel, as head of list
            sentinels = [freelists_addr + i*size_heap_entry]
            for j, freeblock in enumerate(self._iterate_list_from_field_inner(iterator_fn,
                                                                 freelist,
                                                                 self.win_heap.struct__HEAP_ENTRY_0_0,
                                                                 offset,
                                                                 sentinels)):
                #struct__HEAP_ENTRY
                ### winxp ?? if record.EncodeFlagMask:
                ## no need for decode in winxp
                ##chunk_header = self.HEAP_ENTRY_decode(freeblock, record)
                # size = (header + freespace) * sizeof(HEAP_ENTRY) # (2 pointers)
                #if freeblock.Size == 0:
                #    import code
                #    code.interact(local=locals())
                res.append((freeblock._orig_address_, freeblock.Size * self._target.get_word_size()))
                # DEBUG, _orig_address_ has weird addresses
                log.debug('HEAP.FreeLists[%d][%d]: size:0x%x @0x%x', i, j, freeblock.Size * self._target.get_word_size(), freeblock._orig_address_)
        return res

    def HEAP_ENTRY_decode(self, chunk_header, heap):
        return chunk_header

    def HEAP_SEGMENT_get_UCR_segment_list(self, record):
        """Returns a list of UCR segments for this segment.
        HEAP.UCRSegments is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        ucrs = list()
        segments = list()
        # record.segments is a pointer to s single list
        # the field has a different name from win7
        #struct__HEAP_UCR_SEGMENT._fields_ = [
        #('Next', POINTER_T(struct__HEAP_UCR_SEGMENT)),
        ucrs = list()
        for ucr in self.iterate_list_from_field(record, 'UCRSegments'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

