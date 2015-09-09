# -*- coding: utf-8 -*-
#


"""
WinXP HEAP

# if record.FrontEndHeapType == 0
#    record.CommitRoutine != 0
#    record.FrontEndHeap == 0
#    record.LockVariable == 0
#    record.Flags == 9
#    record.ForceFlags == 9
#    record.ProcessHeapsListIndex == 0
#    record.NonDedicatedListLength == 0

('FrontEndHeap', POINTER_T(None)),
is the LAL, an array of 128 entries of 0x30 bytes
for allocation < 1024
There are 128 look-aside lists per heap, which handle allocations up to 1KB on 32-bit systems
and up to 2KB on 64-bit platforms.
http://blogs.technet.com/b/askperf/archive/2007/06/29/what-a-heap-of-part-two.aspx


# ('FreeLists', struct__LIST_ENTRY * 128),
# each one of the 128 list is a double linked list of struct__HEAP_ENTRY
Freelists is used by the backend manager

# AWD: It is critical to note that the pointer listed in the free lists actually points
# to the user-accessible part of the heap block and not to the start of the heap block
# itself. As such, if you want to look at the allocation metadata, you need to first
# subtract 2x wordsize bytes from the pointer.
#
# LXJ: hence, the heap entry contains the LIST_ENTRY pointers in the user allocation part.
# fieldname, pointee_record_type, lefn, offset = link_info
#
for i, freelist in enumerate(record.FreeLists):
    # all freeblocks in this list have the same size


UCR Tracking
Each heap has a portion of memory set aside to track uncommitted ranges of memory.
These are used by the segments to track all of the holes in their reserved address
ranges. The segments track this with small data structures called UCR (Un-committed
Range) entries.

The heap keeps a global list of free UCR entry structures that the heap
segments can request, and it dynamically grows this list to service the needs of the
heap segments.

At the base of the heap, UnusedUnCommittedRanges is a linked list
of the empty UCR structures that can be used by the heap segments. UCRSegments
is a linked list of the special UCR segments used to hold the UCR structures.

When a segment uses a UCR, it removes it from the heap’s
UnusedUnCommittedRanges linked list and puts it on a linked list in the segment
header called UnCommittedRanges. The special UCR segments are allocated
dynamically. The system starts off by reserving 0x10000 bytes for each UCR
segment, and commits 0x1000 bytes (one page) at a time as additional UCR tracking
entries are needed. If the UCR segment is filled and all 0x10000 bytes are used, the
heap manager will create another UCR segment and add it to the UCRSegments list.


        heap_flags = {
            'HEAP_NO_SERIALIZE': 0,
            'HEAP_GROWABLE': 1,
            'HEAP_GENERATE_EXCEPTIONS': 2,
            'HEAP_ZERO_MEMORY': 3,
            'HEAP_REALLOC_IN_PLACE_ONLY': 4,
            'HEAP_TAIL_CHECKING_ENABLED': 5,
            'HEAP_FREE_CHECKING_ENABLED': 6,
            'HEAP_DISABLE_COALESCE_ON_FREE': 7,
            'HEAP_SETTABLE_USER_VALUE': 8,
            'HEAP_CREATE_ALIGN_16': 16,
            'HEAP_CREATE_ENABLE_TRACING': 17,
            'HEAP_CREATE_ENABLE_EXECUTE': 18,
            'HEAP_FLAG_PAGE_ALLOCS': 24,
            'HEAP_PROTECTION_ENABLED': 25,
            'HEAP_CAPTURE_STACK_BACKTRACES': 27,
            'HEAP_SKIP_VALIDATION_CHECKS': 28,
            'HEAP_VALIDATE_ALL_ENABLED': 29,
            'HEAP_VALIDATE_PARAMETERS_ENABLED': 30,
            'HEAP_LOCK_USER_ALLOCATED': 31,
            }

        entry_flags = {
            #'HEAP_ENTRY_BUSY': 0,
            "busy": 0,
            #'HEAP_ENTRY_EXTRA_PRESENT': 1,
            "extra": 1,
            #'HEAP_ENTRY_FILL_PATTERN': 2,
            "fill": 2,
            #'HEAP_ENTRY_VIRTUAL_ALLOC': 3,
            "virtual": 3,
            #'HEAP_ENTRY_LAST_ENTRY': 4,
            "last": 4,
            #'HEAP_ENTRY_SETTABLE_FLAG1': 5,
            "flag1": 5,
            #'HEAP_ENTRY_SETTABLE_FLAG2': 6,
            "flag2": 6,
            #'HEAP_ENTRY_SETTABLE_FLAG3': 7
            "flag3": 7
            }

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
        #self.register_linked_list_field_and_type(self.win_heap.struct__SLIST_HEADER_0, 'Next', self.win_heap.struct__HEAP_ENTRY, 'ListHead')
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

    def HEAP_get_lookaside_chunks(self, record):
        """
         heap->FrontEndheap is a list of 128 HEAP_LOOKASIDE
         lookasidelist[n] block is of size n*8 and used to store (n-1)*8 byte blocks (remaining 8 bytes is used for header

         Most of the time, with FrontEndHeapType == 1 and LockVariable != 0,
            then TotalFreeSize*4 == FreeLists totals, event with LAL present.
        """
        log.debug('HEAP_get_lookaside_chunks')
        ptr = record.FrontEndHeap
        lal_start_addr = self._utils.get_pointee_address(ptr)
        _t = self.win_heap.HEAP_LOOKASIDE * 128
        m = self._memory_handler.is_valid_address(lal_start_addr, _t)
        #get_mapping_for_address(lal_start_addr)
        if not m:
            #raise RuntimeError('HEAP.FrontEndHeap has a bad address %x' % lal_start_addr)
            log.error('HEAP.FrontEndHeap has a bad address %x', lal_start_addr)
            return []
        #st = m.read_struct(addr, self.win_heap.HEAP_LOOKASIDE)
        lal_list = m.read_struct(lal_start_addr, _t)
        lal_entry_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_LOOKASIDE)
        #
        from haystack.outputters.text import RecursiveTextOutputter
        parser = RecursiveTextOutputter(self._memory_handler)

        res = []
        for i, st in enumerate(lal_list):
            if st.ListHead._1.Next.Next.value == 0:
                continue
            #chunk_size = i*8 # free_usable_size = (i-1)*8
            chunk_size = (i-1)*8
            log.debug("LAL depth:%d chunk_size:0x%x @: 0x%x", st.Depth, chunk_size, st.ListHead._1.Next.Next.value)
            res.append((st.ListHead._1.Next.Next.value, chunk_size))
            #continue
            entry = st.ListHead._1
            lal_entry_addr = lal_start_addr + i*lal_entry_size
            entry._orig_address_ = lal_entry_addr
            #for i, lookaside in self.iterate_list_from_field(st, 'ListHead'):
            #for i, lookaside in enumerate(self.iterate_list_from_field(entry, 'Next')):
            # CHECK I think its HEAP_ENTRY in LAL
            #iterator_fn = self._iterate_double_linked_list
            # size is actually a factor of heap granularity == sizeof(HEAP_ENTRY)
            #size_heap_entry = self._ctypes.sizeof(self.win_heap.struct__HEAP_ENTRY_0_0)
            #offset = size_heap_entry
            # get the first entry
            #first_entry_addr = entry.Next.Next.value
            #if first_entry_addr == 0:
            #    continue
            #first_entry_addr += 2*self._target.get_word_size()
            #m = self._memory_handler.is_valid_address(first_entry_addr, self.win_heap.struct__HEAP_ENTRY)
            #if not m:
            #    raise RuntimeError('HEAP.FrontEndHeap.ListHead._1.Next.Next has a bad address %x' % lal_start_addr)
            #first_entry = m.read_struct(first_entry_addr, self.win_heap.struct__HEAP_ENTRY)
            # res.append((first_entry._orig_address_, first_entry.Size * self._target.get_word_size()))
            # every list head is a sentinel, as head of list
            sentinels = [lal_entry_addr]

            #for j, freeblock in enumerate(self._iterate_list_from_field_inner(iterator_fn,
            #                                         first_entry,
            #                                         self.win_heap.struct__HEAP_ENTRY_0_0,
            #                                         offset,
            #                                         sentinels)):
            for j, freeblock in enumerate(self.iterate_list_from_field(entry, 'Next')):
                res.append((freeblock._orig_address_, chunk_size))
                log.debug('HEAP.LAL[%d][%d]: size:0x%x @0x%x', i, j, chunk_size, freeblock._orig_address_)

                #addr = lookaside._orig_address_
                #log.debug('finding lookaside %d at @%x', i, addr)
                #print parser.parse(lookaside)
                #ucr_addr = self._utils.get_pointee_address(ucr.Address)
                #listHead = st.ListHead._1
                #listHead._orig_address_ = addr
                #for free in self.iterate_list_from_field(listHead, 'Next'):
                #    # TODO delete this free from the heap-segment entries chunks
                #    # is that supposed to be a FREE_ENTRY ?
                #    # or a struct__HEAP_LOOKASIDE ?
                #    log.debug('free')
                #    #all_free.append(free)  # ???
                #    pass
                #yield addr, 0
        return res


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
            #log.debug('HEAP.FreeLists[%d]:', i)
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
            # FIXME isn't 2 pointers ?
            offset = size_heap_entry
            # the heap.freelists address
            freelists_addr = record._orig_address_ + self._utils.offsetof(type(record), 'FreeLists')
            # every list head is a sentinel, as head of list
            # FIXME:
            ## if i == 0, 1 or 2, size is not related to the index i
            sentinels = [freelists_addr + i*size_heap_entry]
            # FIXME: backend heap ?
            # if record.FrontEndHeapType == 0
            #    record.CommitRoutine != 0
            #    record.FrontEndHeap == 0
            #    record.LockVariable == 0
            #    record.Flags == 9
            #    record.ForceFlags == 9
            #    record.Entry._0._0.Size == 193
            #    record.ProcessHeapsListIndex == 0
            #    record.NonDedicatedListLength == 0
            # then the freelists points to UCR ?
            #
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

    def get_UCR_segment_list(self, record):
        """Returns a list of UCR segments for this segment.
        HEAP.UCRSegments is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        if not isinstance(record, self.win_heap.struct__HEAP):
            raise TypeError('record should be a heap')
        ucrs = []
        segments = []
        ucr_addr = self._utils.get_pointee_address(record.UCRSegments)
        if ucr_addr == 0:
            return ucrs
        # record.segments is a pointer to s single list
        # the field has a different name from win7
        #struct__HEAP_UCR_SEGMENT._fields_ = [
        #('Next', POINTER_T(struct__HEAP_UCR_SEGMENT)),
        m = self._memory_handler.get_mapping_for_address(ucr_addr)
        if not m:
            log.debug("found a non valid UCRSegments pointer at %x", ucr_addr)
            raise ValueError("found a non valid UCRSegments pointer at %x" % ucr_addr)
        root_ucr = m.read_struct(ucr_addr, self.win_heap.struct__HEAP_UCR_SEGMENT)
        self._memory_handler.keepRef(ucr_addr, self.win_heap.struct__HEAP_UCR_SEGMENT, ucr_addr)
        # FIXME what is this hack
        root_ucr._orig_address_ = ucr_addr
        ucrs.append(ucr_addr)
        for ucr in self.iterate_list_from_field(root_ucr, 'UCRSegments'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    def HEAP_get_chunks(self, record):
        """
        Returns a list of tuple(address,size) for all chunks in
         the backend allocator.
        """
        # FIXME look at segment.LastEntryInSegment
        allocated = list()
        free = list()
        for segment in self.HEAP_get_segment_list(record):
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            # create the skip list for each segment.
            skiplist = dict()
            # FIXME, in XP, ucrsegments is in HEAP, its a pointer
            # in win7 ucrsegmentlist is in heap_segment
            for ucr in self.get_UCR_segment_list(record):
                ucr_addr = self._utils.get_pointee_address(ucr.Address)
                # UCR.Size are not chunks sizes. NOT *8
                skiplist[ucr_addr] = ucr.Size
                log.debug('adding skiplist from %x to %x', ucr_addr, ucr_addr+ucr.Size)
            #
            log.debug('skiplist has %d items', len(skiplist))

            chunk_addr = first_addr
            log.debug('reading chunk from %x to %x', first_addr, last_addr)
            while chunk_addr < last_addr:
                if chunk_addr in skiplist:
                    size = skiplist[chunk_addr]
                    log.debug(
                        'Skipping 0x%0.8x - skip %0.5x bytes to 0x%0.8x',
                        chunk_addr, size, chunk_addr + size)
                    chunk_addr += size
                    continue
                chunk_header = self._memory_handler.getRef(self.win_heap.HEAP_ENTRY, chunk_addr)
                if chunk_header is None:  # force read it
                    log.debug('reading chunk from %x', chunk_addr)
                    m = self._memory_handler.get_mapping_for_address(chunk_addr)
                    # FIXME
                    # in some case, we have the last chunk pointing to the first byte
                    # of the next unallocated mapping offset_X.
                    # in some case, there is a non allocated gap between offset_X and last_addr
                    # FIXME, the skiplist above should address that.
                    if not m:
                        log.debug("found a non valid chunk pointer at %x", chunk_addr)
                        break
                    chunk_header = m.read_struct(chunk_addr, self.win_heap.struct__HEAP_ENTRY)
                    self._memory_handler.keepRef(chunk_header, self.win_heap.struct__HEAP_ENTRY, chunk_addr)
                    # FIXME what is this hack
                    chunk_header._orig_address_ = chunk_addr
                log.debug('\t\tEntry: 0x%0.8x\n%s'%( chunk_addr, chunk_header))
                flags = chunk_header._0._1.Flags
                size = chunk_header._0._0.Size
                if (flags & 1) == 1:
                    log.debug('Chunk 0x%0.8x is in use size: %0.5x', chunk_addr, size * 8)
                    allocated.append((chunk_addr, size * 8))
                else:
                    log.debug('Chunk 0x%0.8x is FREE, size: %0.5x', chunk_addr, size * 8)
                    free.append((chunk_addr, size * 8))
                    if size == 0:
                        log.debug('Free Chunk with 0 size, breaking out')
                        chunk_addr = last_addr
                chunk_addr += size * 8
        return (allocated, free)
