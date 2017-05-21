# -*- coding: utf-8 -*-
#
from __future__ import print_function

"""
Win 7 heap structure validation
See docs/win32_heap for all supporting documentation.

The Heap Manager organizes its virtual memory using heap segments.
Distinction between reserved and committed memory.
Committing memory == mapping/backing the virtual memory.
Uncommitted memory is tracked using UCR entries and segments.

heap_size_including_ucr = heap.Counters.TotalMemoryReserved
segment_space +/- = heap.Segment.LastValidEntry -  heap.Segment.FirstEntry
committed_size = heap.Counters.TotalMemoryCommitted
sum_ucr_size = heap.Counters.TotalMemoryReserved - heap.Counters.TotalMemoryCommitted

heap.Counters.TotalMemoryReserved == heap.LastValidEntry - heap.BaseAddress
UCR and UCRSegments included.

Win7 Heap manager uses either Frontend allocator or Backend allocator.
Default Frontend allocator is Low Fragmentation Heap (LFH).

Chunks are allocated memory.
List of chunks allocated by the backend allocators are linked in
heap.segment.FirstValidEntry to LastValidEntry.
LFH allocations are in one big chunk of that list at heap.FrontEndHeap.

There can be multiple segment in one heap.
Each segment has a FirstEntry (chunk) and LastValidEntry.
FirstEntry <= chunks <= UCR < LastValidEntry

Heap is a segment.
Heap.SegmentList.Flink 0x580010L
Heap.SegmentList.Blink 0x1f00010L
Heap.SegmentList is at offset 0xa8

Heap.SegmentListEntry.Flink 0x1f00010L
Heap.SegmentListEntry.Blink 0x5800a8L
Heap.SegmentListEntry is at offset 0x10

    >>> hex(type(heap).SegmentList.offset)
    '0xa8'
    >>> hex(type(heap).SegmentListEntry.offset)
    '0x10'

So some segment pages ('children mapping') can be found by iterating Segments.
But in some case, the Heap mapping is punched with holes due to Uncommitted Pages. (memory acquisition problem??)
So there is only one segment, which LastValidEntry is > at the mapping end address
Is that a memory acquisition issue ?

Segment: UCRSegmentList
Heap: UCRList

You can fetch chunks tuple(address,size) with HEAP.get_chunks .

You can fetch ctypes segments with HEAP.get_segment_list
You can fetch free ctypes UCR segments with HEAP.get_UCR_segment_list
You can fetch a segment UCR segments with HEAP_SEGMENT.get_UCR_segment_list



"""


import logging

from haystack.abc import interfaces
from haystack.allocators.win32 import winheap


log = logging.getLogger('win7heap')


class Win7HeapValidator(winheap.WinHeapValidator):
    """
    this listmodel Validator will register know important list fields
    in the win7 HEAP,
    [ FIXME TODO and apply constraints ? ]
    and be used to validate the loading of these allocators.
    This class contains all helper functions used to parse the win7heap allocators.
    """

    def __init__(self, memory_handler, my_constraints, target_platform, win7heap_module):
        if not isinstance(memory_handler, interfaces.IMemoryHandler):
            raise TypeError("Feed me a IMemoryHandler")
        if not isinstance(my_constraints, interfaces.IModuleConstraints):
            raise TypeError("Feed me a IModuleConstraints")
        if not isinstance(target_platform, interfaces.ITargetPlatform):
            raise TypeError("Feed me a ITargetPlatform")
        self._ctypes = target_platform.get_target_ctypes()
        super(Win7HeapValidator, self).__init__(memory_handler, my_constraints, self._ctypes)
        # 8 in x32, 16 in x64
        self._word_size = target_platform.get_word_size()
        self._word_size_x2 = self._word_size * 2
        self.win_heap = win7heap_module
        sentinels = set()
        # set some heap_entry
        log.debug('Win7HeapValidator: bits:%d', self._word_size)
        if self._word_size == 4:
            self._lfh_heap_entry_type = self.win_heap.struct__HEAP_ENTRY_0_1
            self._free_list_heap_entry_type = self.win_heap.struct__HEAP_FREE_ENTRY_0_5
            self._sized_heap_entry_type = self.win_heap.struct__HEAP_ENTRY_0_0
        elif self._word_size == 8:
            self._lfh_heap_entry_type = self.win_heap.struct__HEAP_ENTRY_0_0_0_0
            self._free_list_heap_entry_type = self.win_heap.struct__HEAP_FREE_ENTRY_0_2
            self._sized_heap_entry_type = self.win_heap.struct__HEAP_ENTRY_0_0_0_0
        else:
            raise TypeError('platform not supported')

        # register list types
        self.register_single_linked_list_record_type(self.win_heap.SINGLE_LIST_ENTRY, 'Next', sentinels)
        self.register_double_linked_list_record_type(self.win_heap.LIST_ENTRY, 'Flink', 'Blink', sentinels)

        # Segments
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'SegmentList', self.win_heap.HEAP_SEGMENT, 'SegmentListEntry')

        # UCR
        # heap is a heap_segment with more info.
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'UCRSegmentList', self.win_heap.HEAP_UCR_DESCRIPTOR, 'SegmentEntry')
        self.register_linked_list_field_and_type(self.win_heap.HEAP_SEGMENT, 'UCRSegmentList', self.win_heap.HEAP_UCR_DESCRIPTOR, 'SegmentEntry')
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'UCRList', self.win_heap.HEAP_UCR_DESCRIPTOR, 'ListEntry')
        self.register_linked_list_field_and_type(self.win_heap.HEAP_UCR_DESCRIPTOR, 'SegmentEntry', self.win_heap.HEAP_SEGMENT, 'UCRSegmentList')

        # VALLOCS
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'VirtualAllocdBlocks', self.win_heap.HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry')

        # HEAP_ENTRY now works for 32 and 64
        self.register_linked_list_field_and_type(self.win_heap.HEAP, 'FreeLists', self._free_list_heap_entry_type, 'FreeList')

        # LFH
        self.register_linked_list_field_and_type(self.win_heap.LFH_HEAP, 'SubSegmentZones', self.win_heap.LFH_BLOCK_ZONE, 'ListEntry')
        #self.register_linked_list_field_and_type(self.win_heap.HEAP_LOCAL_DATA, 'CrtZone', self.win_heap.LFH_BLOCK_ZONE, 'ListEntry')
        self.register_linked_list_field_and_type(self.win_heap.LFH_BLOCK_ZONE, 'ListEntry', self.win_heap.LFH_BLOCK_ZONE, 'ListEntry')

    def _heap_entry_to_size(self, entry):
        # save to getRef
        if self._word_size == 4:
            return entry._0._0
        elif self._word_size == 8:
            return entry._0._0._1._0

    def _heap_entry_to_lfh(self, entry):
        # save to getRef
        if self._word_size == 4:
            return entry._0._1
        elif self._word_size == 8:
            return entry._0._0._1._0
        return

    def collect_all_ucrs(self, heap):
        ucrs = set()
        for segment in self.get_segment_list(heap):
            for ucr in self.get_UCR_segment_list(segment):
                ucr_addr = self._utils.get_pointee_address(ucr.Address)
                ucr_size = ucr.Size
                ucrs.add((ucr_addr, ucr_size))
        # UCRList
        for ucr in self.HEAP_get_UCRanges_list(heap):
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            ucr_size = ucr.Size
            ucrs.add((ucr_addr, ucr_size))
        return ucrs

    def get_UCR_segment_list(self, segment):
        """Returns a list of UCR segments for this segment.
        HEAP_SEGMENT.UCRSegmentList is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        if not isinstance(segment, self.win_heap.HEAP_SEGMENT) and not isinstance(segment, self.win_heap.HEAP):
            raise TypeError('record should be a heap_segment, not %s' % segment)
        # the record at end_segment-0x10 is not actually invalid.
        # it is a valid HEAP_UCR_DESCRIPTOR. Most of the time, with a Size of 0.
        ucrs = list()
        for ucr in self.iterate_list_from_field(segment, 'UCRSegmentList'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    def HEAP_get_UCRanges_list(self, heap):
        """
        win7
        Returns a list of available UCR segments for this heap.
        HEAP.UCRList is a linked list to all UCRSegments

        """
        if not isinstance(heap, self.win_heap.HEAP):
            raise TypeError('record should be a heap, not %s' % heap)
        ucrs = list()
        for ucr in self.iterate_list_from_field(heap, 'UCRList'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Heap.UCRList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    def UNUSED_HEAP_get_UCRange_segment_list(self, record):
        """
        Returns a list of uncommited segment for this UCR.
        HEAP.UCRList->SegmentEntry is a linked list to all UCRSegments

        """
        expected_type = 'HEAP_UCR_DESCRIPTOR'
        if expected_type not in str(type(record)):
            raise TypeError('record %s should be of type %s' % (record, expected_type))
        entries = list()
        for entry in self.iterate_list_from_field(record, 'SegmentEntry'):
            entry_struct_addr = entry._orig_address_
            entry_addr = self._utils.get_pointee_address(entry.BaseAddress)
            first = entry.FirstEntry.value
            last = entry.LastValidEntry.value
            size = last - first
            log.debug("Heap.UCRList.SegmentEntry: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                entry_struct_addr, entry_addr, size))
            entries.append(entry)
        return entries

    def _get_LFH_SubSegment_from_SubSegmentZones(self, lfh_heap):
        """
        SubSegmentsZones and CrtZone return the same
        :param lfh_heap:
        :return:
        """
        # look at the list of LFH_BLOCK_ZONE
        for lfh_block in self.iterate_list_from_field(lfh_heap, 'SubSegmentZones'):
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

    def get_lfh_chunks(self, heap):
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
        # PY2+PY3 divisions
        array_size = (fp - end)//subseg_size
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
            if heap.EncodeFlagMask:
                # we need chunk_header to a HEAP_ENTRY with UnusedBytes (LFH)
                chunk_header = self.HEAP_ENTRY_decode(chunk_header, heap)
                chunk_header = self._heap_entry_to_lfh(chunk_header)
            else:
                log.error('NOT ENCODED')
                raise TypeError("LFH should not exists on OS without heap.EncodeFlagMask")
            # test if chunk is allocated or free
            if chunk_header.UnusedBytes & 0x38:
                free.add((chunk_addr + 0x8, allocation_length - 0x8))
            else:
                unused_bytes = chunk_header.UnusedBytes & 0x3f - 0x8
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

    def get_segment_list(self, heap):
        """returns a list of all segment attached to one Heap structure."""
        segments = list()
        # self heap is already one segment, but it listed in the list
        # segment = self.win_heap.HEAP_SEGMENT.from_buffer(record)
        # now the list content.
        for segment in self.iterate_list_from_field(heap, 'SegmentList'):
            segment_addr = segment._orig_address_
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            log.debug('Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x', segment_addr, first_addr, last_addr)
            segments.append(segment)
        segments.sort(key=lambda s: self._utils.get_pointee_address(s.FirstEntry))
        return segments

    def print_heap_analysis_details(self, heap):
        # size & space calculated from heap info
        print('    Backend:')
        ucrs = self.HEAP_get_UCRanges_list(heap)
        ucr_list = winheap.UCR_List(ucrs)
        # heap.Counters.TotalMemoryReserved.value == heap.LastValidEntry.value - heap.BaseAddress.value
        nb_ucr = heap.Counters.TotalUCRs
        print('\tUCRList: %d/%d' % (len(ucrs), nb_ucr))
        print(ucr_list.to_string('\t\t'))
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
        nb_segments = heap.Counters.TotalSegments
        ucr_list = winheap.UCR_List(ucrs)

        overhead_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_ENTRY)
        # get allocated/free stats by segment
        occupied_res2 = self.count_by_segment(segments, walker.get_backend_allocations(), overhead_size)
        free_res2 = self.count_by_segment(segments, walker.get_backend_free_chunks(), overhead_size)
        print("\tSegmentList: %d/%d" % (len(segments), nb_segments))
        for segment in segments:
            p_segment = winheap.Segment(self._memory_handler, walker, segment)
            p_segment.set_ucr(ucr_list)
            p_segment.set_resource_usage(occupied_res2, free_res2)
            print(p_segment.to_string('\t\t'))
            # if UCR, then
            ucrsegments = self.get_UCR_segment_list(heap)
            #print "\t\t\tUCRSegmentList: %d {%s}" % (len(ucrsegments), ','.join(sorted([hex(s._orig_address_) for s in ucrsegments])))
            print("\t\t\tUCRSegmentList: %d " % len(ucrsegments))
            for ucr in ucrsegments:
                _addr = self._utils.get_pointee_address(ucr.Address)
                end = _addr + ucr.Size
                print("\t\t\t\tUCRSegment 0x%0.8x-0x%0.8x size:0x%x" % (_addr, end, ucr.Size))
            # print ".UCRSegmentList.Blink", hex(heap.UCRSegmentList.Blink.value)

    def print_frontend_analysis_details(self, heap):
        # Frontend Type == LFH
        if heap.FrontEndHeapType == 2:
            print('    FrontEnd: LOW_FRAGMENTATION_HEAP')
            lfh_heap = self._get_lfh_heap(heap)
            lfh_blocks = [x for x in self._get_LFH_SubSegment_from_SubSegmentZones(lfh_heap)]
            blocks_2 = [b for b in self._get_LFH_SubSegment_from_CrtZone(lfh_heap)]
            print('\t\tLFH Blocks %d/%d' % (len(lfh_blocks), len(blocks_2)))
            _c, _f = self.get_lfh_chunks(heap)
            c_size = sum([c[1] for c in _c])
            u_size = sum([c[2] for c in _c])
            f_size = sum([c[1] for c in _f])
            print('\t\tLFH CommittedSize:0x%x FreeSize:0x%x Unused:0x%x' % (c_size, f_size, u_size))
            mappings = set()
            # we limit the search to UserBlocks, as heap_entries have to be on the same mapping
            for b in lfh_blocks:
                total_size = 0
                start, segments = self.get_lfh_subsegment(b)
                if start is None:
                    print('\t\t\tBlock 0x%0.8x SubSegments: 0' % b._orig_address_)
                    continue
                print('\t\t\tBlock 0x%0.8x SubSegments: %d' % (b._orig_address_, len(segments)))
                for segment in segments:
                    user_blocks_addr = self._utils.get_pointee_address(segment.UserBlocks)
                    if user_blocks_addr == 0:
                        print('\t\t\t\tSubSegment->UserBlocks == NULL')
                        continue
                    mappings.add(self._memory_handler.get_mapping_for_address(user_blocks_addr))
                    allocation_length = segment._3._0.BlockSize * self._word_size_x2
                    block_count = segment._3._0.BlockCount
                    header_size = self._ctypes.sizeof(self.win_heap.struct__HEAP_USERDATA_HEADER)
                    # to the end of last chunk
                    end = user_blocks_addr + header_size + allocation_length * (block_count + 1)
                    size = end-user_blocks_addr
                    print('\t\t\t\tSubSegment 0x%0.8x-0x%0.8x size:0x%x chunks: count:%d size:0x%x' % (user_blocks_addr, end, size, block_count, allocation_length))
                    total_size += size
                    # occupied_res3 = self.count_by_segment(segments, walker.get_user_allocations(), overhead_size)
                    # free_res3 = self.count_by_segment(segments, walker.get_free_chunks(), overhead_size)

                # sum of all user blocks for this subsegment
                print('\t\t\tTotal_committed_size:0x%0.8x' % total_size)
            print('\t\tMappings used:')
            for m in sorted(mappings, key=lambda x: x.start):
                print('\t\t\t%s' % m)
        return

