# -*- coding: utf-8 -*-
#


from __future__ import print_function

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
ranges. The segments track this with small data allocators called UCR (Un-committed
Range) entries.

The heap keeps a global list of free UCR entry allocators that the heap
segments can request, and it dynamically grows this list to service the needs of the
heap segments.

At the base of the heap, UnusedUnCommittedRanges is a linked list
of the empty UCR allocators that can be used by the heap segments. UCRSegments
is a linked list of the special UCR segments used to hold the UCR allocators.

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

import logging

from haystack.abc import interfaces
from haystack.allocators.win32 import winheap

log = logging.getLogger('winxpheap')


class WinXPHeapValidator(winheap.WinHeapValidator):
    """
    this listmodel Validator will register know important list fields
    in the winxp HEAP,
    and be used to validate the loading of these allocators.
    This class contains all helper functions used to parse the winxpheap allocators.
    """

    def p(self, ss):
        # FIXME DEBUG
        from haystack.outputters import text
        parser = text.RecursiveTextOutputter(self._memory_handler)
        return parser.parse(ss)

    def __init__(self, memory_handler, my_constraints, target_platform, winxpheap_module):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        if not isinstance(target_platform, interfaces.ITargetPlatform):
            raise TypeError("Feed me a ITargetPlatform")
        self._ctypes = target_platform.get_target_ctypes()
        super(WinXPHeapValidator, self).__init__(memory_handler, my_constraints, self._ctypes)
        # 8 in x32, 16 in x64
        self._word_size = target_platform.get_word_size()
        self._word_size_x2 = self._word_size * 2
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
        # sentinels = [mapping.end-0x10 for mapping in self._memory_handler.get_mappings()]
        sentinels = set([mapping.end for mapping in self._memory_handler.get_mappings()])
        sentinels.add(0xffffffff)

        self.register_single_linked_list_record_type(self.win_heap.SINGLE_LIST_ENTRY, 'Next', sentinels)
        self.register_double_linked_list_record_type(self.win_heap.LIST_ENTRY, 'Flink', 'Blink', sentinels)

        self.register_linked_list_field_and_type(self.win_heap.SINGLE_LIST_ENTRY, 'Next', self.win_heap.SINGLE_LIST_ENTRY, 'Next')

        #
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'VirtualAllocdBlocks', self.win_heap.struct__HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry') # offset = -8
        # 32 bits
        if self._word_size == 4:
            self.register_linked_list_field_and_type(self.win_heap.struct__SLIST_HEADER_0, 'Next', self.win_heap.struct__HEAP_LOOKASIDE, 'ListHead')
        else:
            pass
        # winxp 64
        # cast(SLIST_HEADER.Region, SINGLE_LIST_ENTRY ?
        self.register_single_linked_list_record_type(self.win_heap.struct__HEAP_UCR_SEGMENT, 'Next', sentinels)

        # UCR
        # ('UnusedUnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)), Next, Address, Size
        self.register_single_linked_list_record_type(self.win_heap.struct__HEAP_UNCOMMMTTED_RANGE, 'Next', sentinels)
        self.register_linked_list_field_and_type(self.win_heap.struct__HEAP_UNCOMMMTTED_RANGE, 'Next', self.win_heap.struct__HEAP_UNCOMMMTTED_RANGE, 'Next')

        return

    # 2015-06-30 modified for windows xp
    #('Segments', POINTER_T(struct__HEAP_SEGMENT) * 64),
    def get_segment_list(self, record):
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


    def _get_LFH_SubSegment_from_SubSegmentZones(self, lfh_heap):
        """
        SubSegmentsZones and CrtZone return the same
        :param lfh_heap:
        :return:
        """
        # look at the list of LFH_BLOCK_ZONE
        for lfh_block in self.iterate_list_from_field(lfh_heap, 'SubSegmentZones', ignore_head=False):
            yield lfh_block

    def _get_LFH_SubSegment_from_CrtZone(self, lfh_heap):
        """
        SubSegmentsZones and CrtZone return the same
        :param lfh_heap:
        :return:
        """
        # get the local Data
        heap_local_data = lfh_heap.LocalData[0]
        # look at the list of LFH_BLOCK_ZONE
        for lfh_block in self.iterate_list_from_pointer_field(heap_local_data.CrtZone, 'ListEntry'):
            yield lfh_block

    def _get_lfh_heap(self, heap):
        addr = self._utils.get_pointee_address(heap.FrontEndHeap)
        log.debug('finding frontend at @%x' % addr)
        m = self._memory_handler.get_mapping_for_address(addr)
        lfh_heap = m.read_struct(addr, self.win_heap.LFH_HEAP)
        heap_addr = self._utils.get_pointee_address(lfh_heap.Heap)
        if heap_addr != heap._orig_address_:
            log.error("heap->FrontEndHeap->Heap 0x%0x is not a pointer to heap" % heap_addr)
        return lfh_heap

    def TODO_get_lfh_chunks(self, heap):
        """
        http://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux/

        http://rekall-forensic.blogspot.com/2014/12/the-windows-user-mode-heap-and-dns.html
        The LFH claims sub-segments from the backend allocator.
        Each subsegment starts with a _HEAP_USERDATA_HEADER and it is followed by
        an array of allocations of the same size.
        Each such allocation has a _HEAP_ENTRY at the start.
        To the backend allocator the subsegments simply look like largish opaque allocations
        (and are therefore also contained in a backend _HEAP_ENTRY ).

        The LFH reuses the _HEAP_ENTRY struct (again encoded with the heap’s key) to describe each allocation,
        but since all entries in a subsegments are the same size, there is no need to use
        Size andPreviousSize to track them.

        The _HEAP_ENTRY.UnusedBytes member describes how many bytes are unused in the allocation (e.g. if the
        allocation is 20 bytes but the user only wanted 18 bytes there are 2 bytes unused), and also contains flags
        to indicate if the entry is BUSY or FREE.
        """
        all_free = set()
        all_committed = set()
        lfh_heap = self._get_lfh_heap(heap)
        # look at the list of LFH_BLOCK_ZONE
        for lfh_block in self._get_LFH_SubSegment_from_SubSegmentZones(lfh_heap):
            start, segments = self.get_lfh_subsegment(lfh_block)
            if start is None:
                continue
            subseg_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_SUBSEGMENT)
            for i, segment in enumerate(segments):
                segment_addr = start + i*subseg_size
                segment._orig_address_ = segment_addr
                # get the heap entry chunks for that sub segment
                _c, _f = self.get_lfh_subsegment_heap_chunks(heap, segment)
                if _c is not None:
                    all_committed |= _c
                    all_free |= _f
        return all_committed, all_free

    def get_lfh_subsegment(self, lfh_block):
        """
        Return start, sub segments
        :param lfh_block:
        :return:
        """
        lfh_block_addr = lfh_block._orig_address_
        # LFH_BLOCK_ZONE contains a list field to other LFH_BLOCK_ZONE, a FreePointer and a limit
        end = lfh_block_addr + self._ctypes.sizeof(lfh_block)
        fp = self._utils.get_pointee_address(lfh_block.FreePointer)
        # that is a sentinels.
        if fp == (0x10 + self._ctypes.sizeof(lfh_block)):
            log.debug('Got a special FreePointer value 0x%x' % fp)
            return None, None
        # Segments are running from after the lfh_block to the FreePointer
        subseg_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_SUBSEGMENT)
        array_size = (fp - end)/subseg_size
        # in case the pointer is elsewhere
        memory_map = self._memory_handler.get_mapping_for_address(lfh_block_addr)
        return end, memory_map.read_struct(end, self.win_heap.HEAP_SUBSEGMENT*array_size)

    def get_lfh_subsegment_heap_chunks(self, heap, segment):
        """
        Parse the array of heap_entry from segment->UserBlocks++
        :param segment: the heap subsegment
        :return:
        """
        free = set()
        committed = set()
        # segment.LocalInfo holds pointer to a struct__HEAP_LOCAL_SEGMENT_INFO
        # segment.UserBlocks holds a pointer to struct__HEAP_USERDATA_HEADER

        # all heap entries will have the same size
        allocation_length = segment._3._0.BlockSize * self._word_size_x2
        block_count = segment._3._0.BlockCount
        #print 'allocation_length: %s' % hex(allocation_length),
        #print 'BlockCount', block_count,

        # LocalInfo
        # read UserBlocks as USERDATA_HEADER
        user_blocks_addr = self._utils.get_pointee_address(segment.UserBlocks)
        if user_blocks_addr == 0:
            return set(), set()
        ##if user_blocks_addr in done:
        ##    break
        ##done.add(user_blocks_addr)

        # in case userblock is in another mapping
        _map = self._memory_handler.get_mapping_for_address(user_blocks_addr)
        if not _map:
            raise ValueError('Mapping not found for 0x%x' % user_blocks_addr)
        user_blocks = _map.read_struct(user_blocks_addr, self.win_heap.struct__HEAP_USERDATA_HEADER)
        if user_blocks._0._1.Signature != 0xf0e0d0c0:
            log.error("USERDATA_HEADER.Signature: 0x%x", user_blocks._0._1.Signature)
            raise ValueError('USERDATA_HEADER.Signature not 0xf0e0d0c0')
        # Validating the backlink from segment.UserBlocks.subsegment
        _subseg_addr = self._utils.get_pointee_address(user_blocks._0._1.SubSegment)
        if _subseg_addr != segment._orig_address_:
            raise ValueError('segment->UserBlocks->Subsegment should be segment')

        header_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_USERDATA_HEADER)
        ## TODO, is the chunk_type_size actually platform dependant or not?
        chunk_type_size = self._word_size_x2
        # we have an array of block_count * HEAP_ENTRY chunks of size allocation_length
        for i in range(block_count):
            chunk_addr = user_blocks_addr + header_size + i*allocation_length
            chunk_header = _map.read_struct(chunk_addr, self.win_heap.HEAP_ENTRY)
            ###################### FIXME DUP CODE CODE CHANGE BEGIN
            #if heap.EncodeFlagMask:
            #    # we need chunk_header to a HEAP_ENTRY with UnusedBytes (LFH)
            #    chunk_header = self.HEAP_ENTRY_decode(chunk_header, heap)
            #    chunk_header = self._heap_entry_to_lfh(chunk_header)
            #else:
            #    log.error('NOT ENCODED')
            #    raise TypeError("LFH should not exists on OS without heap.EncodeFlagMask")
            # test if chunk is allocated or free
            if chunk_header._1._0.UnusedBytes & 0x38:
                free.add((chunk_addr + 0x8, allocation_length - 0x8))
            else:
                unused_bytes = chunk_header._1._0.UnusedBytes & 0x3f - 0x8
                ###################### FIXME DUP CODE CHANGE END
                data_len = allocation_length - unused_bytes
                if data_len > allocation_length - 0x8:
                    data_len -= 0x8
                if data_len <= 0:
                    log.error('can have allocation < 0: %d' % data_len)
                    raise ValueError('can have allocation < 0: %d' % data_len)
                # buf = _map.read_bytes(chunk_addr + chunk_type_size, data_len)
                # print hex(chunk_addr), buf#, repr(buf)
                committed.add((chunk_addr + chunk_type_size, data_len, unused_bytes))
        # print "commited:%d usedsize:0x%x unusedsize:0x%x" % (len(committed), sum([c[1] for c in committed]), sum([c[2] for c in committed])),
        # print "free:%d size:0x%x" % (len(free), sum([c[1] for c in free]))
        return committed, free

    def get_lfh_subsegment_heap_chunks_fast(self, subsegment):
        """
        Dont validate anything
        """
        userblocks_addr = self._utils.get_pointee_address(subsegment.UserBlocks)
        if not bool(userblocks_addr):
            log.error('Userblocks is null')
            return []
        # the structure is astructure in an unnamed union of self
        st = subsegment._3._0
        # its basically an array of self.BlockCount blocks of self.BlockSize*8/16
        # bytes.
        allocation_length = st.BlockSize * self._word_size_x2
        log.debug('fetching %d blocks of %d bytes' % (st.BlockCount, allocation_length))
        # UserBlocks points to HEAP_USERDATA_HEADER.
        # Real user data blocks will starts after sizeof( HEAP_USERDATA_HEADER )
        header_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_USERDATA_HEADER)
        # each chunk starts with a 8/16 byte header + n user-writeable data
        # user free writable chunk starts with 2 bytes for next offset
        userblocks = [(userblocks_addr + header_size + allocation_length * i, allocation_length)
                       for i in range(st.BlockCount)]
        return userblocks

    def get_lookaside_chunks(self, record):
        """
         heap->FrontEndheap is a list of 128 HEAP_LOOKASIDE
         lookasidelist[n] block is of size n*8 and used to store (n-1)*8 byte blocks (remaining 8 bytes is used for header
         lookasidelist[n] for n = 0,1 are not used.

         Most of the time, with FrontEndHeapType == 1 and LockVariable != 0,
            then TotalFreeSize*4 == FreeLists totals, event with LAL present.
        """
        log.debug('HEAP_get_lookaside_chunks')
        ptr = record.FrontEndHeap
        lal_start_addr = self._utils.get_pointee_address(ptr)
        _t = self.win_heap.HEAP_LOOKASIDE * 128
        m = self._memory_handler.is_valid_address(lal_start_addr, _t)
        if not m:
            log.error('HEAP.FrontEndHeap has a bad address %x', lal_start_addr)
            return set()
        lal_list = m.read_struct(lal_start_addr, _t)
        lal_entry_size = self._ctypes.sizeof(self.win_heap.HEAP_LOOKASIDE)
        #
        all_chunks = set()
        for i, st in enumerate(lal_list):
            if i == 0 or i == 1:
                # log.debug("LAL:%d UNUSED", i)
                continue
            lal_entry_addr = lal_start_addr + i*lal_entry_size
            chunk_size = i * 8
            # - 8 bytes header
            #self._word_size_x2
            # get all chunks in this lal
            this_chunks = set()
            # x64 is different
            if self._word_size == 8:
                # so in x64, not a 64 pointer ? What is ListHead.Region ?
                # http://doxygen.reactos.org/d5/d52/slist_8c_source.html
                # http://stackoverflow.com/questions/20003455/windows-x64-intrusive-singly-linked-list
                # sadly our profiles don't have bitfields.
                depth = st.ListHead.Alignment & 0xffff
                first_entry_addr = st.ListHead.Alignment >> 21
            else:
                # https://www.insomniasec.com/downloads/publications/Heaps_About_Heaps.ppt
                depth = st.ListHead._1.Depth
                first_entry_addr = self._utils.get_pointee_address(st.ListHead._1.Next.Next)

            # sanity checks
            if depth == 0 and first_entry_addr != 0:
                log.warning('depth == 0 and first_entry_addr != 0')
            elif depth != 0 and first_entry_addr == 0:
                log.warning('depth == %d and first_entry_addr == 0' % depth)
            if first_entry_addr == 0:
                log.debug("LAL:%d depth:%d chunk_size:0x%x nb_chunks:0", i, depth, chunk_size)
                continue
            #
            if True: #self._word_size == 8:
                # loop through the list.
                # LAL[2] has a weird pointer.
                if first_entry_addr & 1:
                    entry_addr = first_entry_addr ^ 1
                else:
                    entry_addr = first_entry_addr
                # stop when Null
                # stop on dups. (shouldn't happen)
                # stop on listed depth (will happen)
                while entry_addr != 0 and len(this_chunks) < depth:
                    #
                    m = self._memory_handler.get_mapping_for_address(entry_addr)
                    if not m:
                        log.error('LAL:%d 0x%x is not valid - escaping' % (i, entry_addr))
                        break
                    # keep it
                    this_chunks.add(entry_addr)
                    # go to next one
                    st = m.read_struct(entry_addr, self.win_heap.SINGLE_LIST_ENTRY)
                    entry_addr = self._utils.get_pointee_address(st.Next)
            else:
                # FIXME should work, doesn't
                entry = m.read_struct(first_entry_addr, self.win_heap.SINGLE_LIST_ENTRY)
                this_chunks.add(first_entry_addr)
                for j, freeblock in enumerate(self.iterate_list_from_field(entry, 'Next', sentinels=set(), ignore_head=False)):
                    this_chunks.add(freeblock._orig_address_)

            #print [hex(a) for a in this_chunks]

            # closure for this LAL
            nb = len(this_chunks)
            size = nb*chunk_size
            if nb != depth:
                log.warning('Incorrect depth:%d found:%d' % (depth, nb))
            log.debug("LAL:%d depth:%d chunk_size:0x%x nb_chunks:%d t_size:0x%x", i, depth, chunk_size, nb, size)
            #print "LAL:%d depth:%d chunk_size:0x%x nb_chunks:%d t_size:0x%x" % (i, depth, chunk_size, nb, size)
            for addr in this_chunks:
                all_chunks.add((addr, chunk_size))

        return all_chunks


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
            sentinels = {freelists_addr + i*size_heap_entry}
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
                res.append((freeblock._orig_address_, freeblock.Size * self._word_size))
                # DEBUG, _orig_address_ has weird addresses
                log.debug('HEAP.FreeLists[%d][%d]: size:0x%x @0x%x', i, j, freeblock.Size * self._word_size, freeblock._orig_address_)
        return res

    def HEAP_ENTRY_decode(self, chunk_header, heap):
        return chunk_header

    def collect_all_ucrs(self, heap):
        ucrs = set()
        # UnCommittedRanges
        for segment in self.get_segment_list(heap):
            for ucr in self.SEGMENT_get_UCR_list(segment):
                ucr_addr = self._utils.get_pointee_address(ucr.Address)
                ucr_size = ucr.Size
                ucrs.add((ucr_addr, ucr_size))
        # UCRSegments
        for ucr in self.get_UCR_segment_list(heap):
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            ucr_size = ucr.Size
            ucrs.add((ucr_addr, ucr_size))
        # UnusedUnCommittedRanges
        for ucr in self.HEAP_get_UCRanges_list(heap):
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            ucr_size = ucr.Size
            ucrs.add((ucr_addr, ucr_size))
        return ucrs

    def get_UCR_segment_list(self, record):
        """Returns a list of UCR segments for this segment.
        HEAP.UCRSegments is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        if not isinstance(record, self.win_heap.struct__HEAP):
            raise TypeError('record should be a heap, not %s' % record)
        ucrs = []
        for ucr in self.iterate_list_from_pointer_field(record.UCRSegments, 'Next'):
            ucr_struct_addr = ucr._orig_address_
            log.debug("Segment.UCRSegmentList: 0x%0.8x reserved_size: 0x%0.5x committed_size: 0x%0.5x" % (
                ucr_struct_addr, ucr.SizeReservedSize, ucr.CommittedSize))
            ucrs.append(ucr)
        return ucrs

    def HEAP_get_UCRanges_list(self, record):
        """
        Returns a list of available UCR ranges for this heap.
        HEAP.UnusedUnCommittedRanges is a linked list to all UCRSegments
        ('UnusedUnCommittedRanges', POINTER_T(struct__HEAP_UNCOMMMTTED_RANGE)),
        They are often null. Address == 0, Size == 0

        """
        if not isinstance(record, self.win_heap.struct__HEAP):
            raise TypeError('record should be a heap')
        ucrs = []
        for ucr in self.iterate_list_from_pointer_field(record.UnusedUnCommittedRanges, 'Next'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = ucr.Address
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Heap.UnusedUnCommittedRanges: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            if ucr_addr == 0:
                # ignore it
                continue
            ucrs.append(ucr)
        return ucrs

    def SEGMENT_get_UCR_list(self, record):
        """Returns a list of UCR segments for this segment.
        SEGMENT.UnCommittedRanges is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        if not isinstance(record, self.win_heap.struct__HEAP_SEGMENT):
            raise TypeError('record should be a heap')
        ucrs = []
        for ucr in self.iterate_list_from_pointer_field(record.UnCommittedRanges, 'Next'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = ucr.Address
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Heap.UnusedUnCommittedRanges: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            if ucr_addr == 0:
                # ignore it
                continue
            ucrs.append(ucr)
        return ucrs

    def get_backend_chunks2(self, record):
        """
        Returns a list of tuple(address,size) for all chunks in
         the backend allocator.
        """
        # FIXME look at segment.LastEntryInSegment
        allocated = set()
        free = set()
        for segment in self.get_segment_list(record):
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
                log.debug('\t\tEntry: 0x%0.8x\n%s', chunk_addr, chunk_header)
                flags = chunk_header._0._1.Flags
                size = chunk_header._0._0.Size
                # FIXME BUSY, BACKEND or FRONTEND
                if (flags & 1) == 1:
                    log.debug('Chunk 0x%0.8x is in use size: %0.5x', chunk_addr, size * 8)
                    allocated.add((chunk_addr, size * 8))
                else:
                    log.debug('Chunk 0x%0.8x is FREE, size: %0.5x', chunk_addr, size * 8)
                    free.add((chunk_addr, size * 8))
                    if size == 0:
                        log.debug('Free Chunk with 0 size, breaking out')
                        chunk_addr = last_addr
                chunk_addr += size * 8
        return allocated, free

    def print_heap_analysis_details(self, heap):
        # size & space calculated from heap info
        # winXP
        # Heap's unuseduncommitted ranges
        # Heap.UnusedUnCommittedRanges
        # size & space calculated from heap info
        print('    Backend:')
        ucrs = self.HEAP_get_UCRanges_list(heap)
        ucr_list = winheap.UCR_List(ucrs)
        print('\tUnused UCR: %d' % (len(ucrs)))
        print(ucr_list.to_string('\t\t'))
        # Heap.UCRSegments
        ucrsegments = self.get_UCR_segment_list(heap)
        print("\t\t\tUCRSegments: %d {%s}" % (len(ucrsegments), ','.join(sorted([hex(s._orig_address_) for s in ucrsegments]))))
        for ucr_segment in ucrsegments:
            print("\t\t\t\tUCRSegment: 0x%0.8x-0x%0.8x size:0x%x" % (ucr_segment.Address, ucr_segment.Address+ucr_segment.Size, ucr_segment.Size))
            # print "\t\t\t\t.Segment.Next", hex(ucr_segment.Next.value)
        # Virtual Allocations
        vallocs = self.HEAP_get_virtual_allocated_blocks_list(heap)
        print('\tVAllocations: %d' % len(vallocs))
        for addr, c_size, r_size in vallocs:
            diff = '' if c_size == r_size else '!!'
            # print "vallocBlock: @0x%0.8x commit: 0x%x reserved: 0x%x" % (
            print("\t\t%svalloc: 0x%0.8x-0x%0.8x size:0x%x requested:0x%x " % (diff, addr, addr+c_size, c_size, r_size))
        return ucrs

    def print_segments_analysis(self, heap, walker, ucrs):

        # heap is a segment
        segments = self.get_segment_list(heap)

        overhead_size = self._memory_handler.get_target_platform().get_target_ctypes().sizeof(self.win_heap.struct__HEAP_ENTRY)
        # get allocated/free stats by segment
        occupied_res2 = self.count_by_segment(segments, walker.get_backend_allocations(), overhead_size)
        free_res2 = self.count_by_segment(segments, walker.get_backend_free_chunks(), overhead_size)

        print("\tSegmentList: %d" % len(segments))
        for segment in segments:
            p_segment = winheap.Segment(self._memory_handler, walker, segment)
            # add segments's ucr
            ucrsegments = self.SEGMENT_get_UCR_list(segment)
            ucrs.extend(ucrsegments)
            ucr_list = winheap.UCR_List(ucrs)
            p_segment.set_ucr(ucr_list)
            p_segment.set_resource_usage(occupied_res2, free_res2)
            print(p_segment.to_string('\t\t'))
            # if UCR, then
            # in XP, UCR segments are in HEAP.
            # ucrsegments = validator.get_UCR_segment_list(segment)
            ucrsegments = self.SEGMENT_get_UCR_list(segment)
            print("\t\t\tUCRSegments: %d {%s}" % (len(ucrsegments), ','.join(sorted([hex(s._orig_address_) for s in ucrsegments]))))
            for ucr_segment in ucrsegments:
                print("\t\t\t\tUCRSegment: 0x%0.8x-0x%0.8x size:0x%x" % (ucr_segment.Address, ucr_segment.Address+ucr_segment.Size, ucr_segment.Size))
                #print "\t\t\t\t.Segment.Next", hex(ucr_segment.Next.value)
            #

    def print_frontend_analysis_details(self, heap):
        # get_lookaside_chunks
        return

