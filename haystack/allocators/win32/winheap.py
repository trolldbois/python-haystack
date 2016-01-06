# -*- coding: utf-8 -*-
#
"""
Contains common code for winXP heap and win7 heap
"""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"


import ctypes
import logging

from haystack import listmodel

log = logging.getLogger('winheap')

FrontEndHeapType = {
    0: "BACKEND",
    1: "LOOK_ASIDE",
    2: "LOW_FRAGMENTATION",
    }


class Win_Heap(object):
    def __init__(self, memory_handler, walker):
        self.walker = walker
        self.heap = walker._heap
        validator = walker._validator


class UCR_List(object):
    # based on win7 heap_segment
    def __init__(self, ctypes_ucrlist):
        self.ucrs = [UCR(u) for u in ctypes_ucrlist]

    def to_string(self, prefix=''):
        s = []
        for ucr in self.ucrs:
            #s.append('%sUCR: 0x%0.8x-0x%0.8x => size:0x%x' % (prefix, ucr.Address.value, ucr.Address.value + ucr.Size, ucr.Size))
            s.append('%sUCR: 0x%0.8x-0x%0.8x => size:0x%x' % (prefix, ucr.address, ucr.end, ucr.size))
            ## ucr_segment == heap_segment => heap, its a trap.
        return '\r\n'.join(s)

    def __iter__(self):
        for u in self.ucrs:
            yield u

class UCR(object):
    def __init__(self, ucr):
        self.address = ucr.Address.value if hasattr(ucr.Address, 'value') else ucr.Address
        self.size = ucr.Size
        self.end = self.address + self.size


class Segment(object):
    # based on win7 heap_segment
    # a segment can have multiple mappings

    def __init__(self, memory_handler, ctypes_segment):
        _utils = memory_handler.get_target_platform().get_target_ctypes_utils()
        self.start = _utils.get_pointee_address(ctypes_segment.FirstEntry)
        self.end = _utils.get_pointee_address(ctypes_segment.LastValidEntry)
        #self.start = ctypes_segment.FirstEntry.value
        #self.end = ctypes_segment.LastValidEntry.value
        # UCR.
        self.nb_pages = ctypes_segment.NumberOfPages
        self.uncommitted_pages = ctypes_segment.NumberOfUnCommittedPages
        self.uncommitted_ranges = ctypes_segment.NumberOfUnCommittedRanges
        self.committed_pages = self.nb_pages - self.uncommitted_pages
        self.committed_size = self.committed_pages * 4096
        # gets reduced by set_ucr()
        self.committed_size2 = self.end - self.start
        self.ucrs = []
        # stats from chunks
        self.s_allocated, self.s_allocated_overhead = None, None
        self.s_free, self.s_free_overhead = None, None
        self.s_overhead, self.s_sum = None, None
        self.mappings = self._init_mappings(memory_handler)
        return

    def set_ucr(self, ucr_info):
        for ucr in ucr_info:
            if self.start <= ucr.address <= self.end:
                self.ucrs.append((ucr.address, ucr.size))
                self.committed_size2 -= ucr.size
                pass
        # self.committed_size == self.committed_size2
        return

    def _init_mappings(self, memory_handler):
        mappings = []
        for m in memory_handler.get_mappings():
            if self.start <= m.start < self.end:
                mappings.append(m)
            elif self.start in m:
                mappings.append(m)
        return mappings

    def set_ressource_usage(self, occupied_res, free_res):
        # do the stats
        self.s_allocated, self.s_allocated_overhead = occupied_res.get(self.start, (0, 0))
        self.s_free, self.s_free_overhead = free_res.get(self.start, (0, 0))
        self.s_overhead = self.s_allocated_overhead + self.s_free_overhead
        self.s_sum = self.s_allocated + self.s_free + self.s_overhead
        return

    def to_string(self, prefix=''):
        nb = self.uncommitted_pages
        s = '%sSegment: 0x%0.8x-0x%0.8x size:0x%x' % (prefix, self.start, self.end, self.end-self.start)
        s += "\r\n%s\tNumberOfUnCommittedPages %d => size:0x%x" % (prefix, nb, nb*4096)
        s += "\r\n%s\tNumberOfUnCommittedRanges %d " % (prefix, self.uncommitted_ranges)
        s += '\r\n%s\tcommitted pages size: 0x%x cnt:%d/%d' % (prefix, self.committed_size, self.committed_pages, self.nb_pages)
        if_error = '' if self.committed_size2 == self.s_sum else '!! '
        s += '\r\n%s\t%sExpected committed size:0x%x' % (prefix, if_error, self.committed_size2)
        s += '\r\n%s\t%sVerified committed size:0x%x alloc:0x%x free:0x%x overhead:0x%x' % (prefix, if_error, self.s_sum, self.s_allocated, self.s_free, self.s_overhead)
        s += '\r\n%s\tMappings used:' % prefix
        for m in self.mappings:
            s += '\r\n%s\t\t%s' % (prefix, m)
        # FALSE due to holes (lastValidEntry - m.end) == ctypes_heap.NumberOfUnCommittedPages * 4096:
        return s


class WinHeapValidator(listmodel.ListModel):
    """
    this listmodel Validator will register know important list fields
    in the windows HEAP,
    and be used to validate the loading of these allocators.
    This class contains all helper functions used to parse the windows heap allocators.
    Common code between winXP and win7
    """


    def get_segment_list(self, record):
        raise NotImplementedError('code differs between XP and 7')

    def HEAP_get_virtual_allocated_blocks_list(self, record):
        """
        Returns a list of addr,commited_size, reserved_size virtual allocated entries.
        """
        vallocs = list()
        for valloc in self.iterate_list_from_field(record, 'VirtualAllocdBlocks'):
            addr = valloc._orig_address_
            # committed
            c_size = valloc.CommitSize
            # requested
            r_size = valloc.ReserveSize
            vallocs.append((addr, c_size, r_size))
            log.debug("vallocBlock: @0x%0.8x commit: 0x%x reserved: 0x%x" % (addr, c_size, r_size))
        return vallocs

    ## TODO HEAP UCR and Segment UCR are the same.
    # rename functions to show that better.
    # some heap UCR will not be listed in segment ucr and vice-versa
    # get_ucr == get_ucr_from_heap + get_ucr_from_segment

    def get_UCR_segment_list(self, record):
        """Returns a list of UCR segments for this segment.
        HEAP_SEGMENT.UCRSegmentList is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        # the record at end_segment-0x10 is not actually invalid.
        # it is a valid HEAP_UCR_DESCRIPTOR. Most of the time, with a Size of 0.
        ucrs = list()
        for ucr in self.iterate_list_from_field(record, 'UCRSegmentList'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    def HEAP_get_UCRanges_list(self, record):
        """
        win7
        Returns a list of available UCR segments for this heap.
        HEAP.UCRList is a linked list to all UCRSegments

        """
        # TODO: exclude UCR segment from valid pointer values in _memory_handler.
        ucrs = list()
        for ucr in self.iterate_list_from_field(record, 'UCRList'):
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

    def get_backend_chunks(self, record):
        """
        Returns a list of tuple(address,size) for all chunks in
         the backend allocator.
        """
        allocated = set()
        free = set()
        # FIXME look at segment.LastEntryInSegment
        for segment in self.get_segment_list(record):
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            # create the skip list for each segment.
            skiplist = dict()
            # FIXME, common UCR management for XP and win7
            for ucr in self.get_UCR_segment_list(segment):
                ucr_addr = self._utils.get_pointee_address(ucr.Address)
                # UCR.Size are not chunks sizes. NOT *8
                skiplist[ucr_addr] = ucr.Size
                log.debug('adding skiplist from %x to %x', ucr_addr, ucr_addr+ucr.Size)
            #
            log.debug('skiplist has %d items', len(skiplist))
            _allocated,_free = self._iterate_chunk_list(record, first_addr, last_addr, skiplist)
            allocated |= _allocated
            free |= _free
        return allocated, free

    def _iterate_chunk_list(self, heap, first_addr, last_addr, skiplist):
            allocated = set()
            free = set()
            chunk_addr = first_addr
            log.debug('reading chunk from %x to %x', first_addr, last_addr)
            while chunk_addr < last_addr:
                if chunk_addr in skiplist:
                    size = skiplist[chunk_addr]
                    log.debug('Skipping 0x%0.8x - skip %0.5x bytes to 0x%0.8x', chunk_addr, size, chunk_addr + size)
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
                    chunk_header = m.read_struct(chunk_addr, self.win_heap.HEAP_ENTRY)
                    self._memory_handler.keepRef(chunk_header, self.win_heap.HEAP_ENTRY, chunk_addr)
                    # FIXME what is this hack
                    chunk_header._orig_address_ = chunk_addr
                if heap.EncodeFlagMask:  # heap.EncodeFlagMask
                    chunk_header = self.HEAP_ENTRY_decode(chunk_header, heap)
                # test if chunk is allocated or free
                if (chunk_header.Flags & 1) == 1:
                    allocated.add((chunk_addr, chunk_header.Size * self._word_size_x2))
                else:
                    if chunk_header.Size == 0:
                        log.warning("Null sized free chunk at 0x%0.8x - exiting", chunk_addr)
                        break
                    free.add((chunk_addr, chunk_header.Size * self._word_size_x2))
                    pass
                chunk_addr += chunk_header.Size * self._word_size_x2
            return allocated, free

    def get_lookaside_chunks(self, record):
        """
        WinXP Only
         heap->FrontEndheap is a list of 128 HEAP_LOOKASIDE
         lookasidelist[n] block is of size n*8 and used to store (n-1)*8 byte blocks (remaining 8 bytes is used for header

         Most of the time, with FrontEndHeapType == 1 and LockVariable != 0,
            then TotalFreeSize*4 == FreeLists totals, event with LAL present.
        """
        raise NotImplementedError

    def get_lfh_chunks(self, record):
        """
        Win7 only
        """
        raise NotImplementedError

    def get_frontend_chunks(self, heap):
        """
        Return the committed and free space from the frontend allocator.
        Will raise a TypeError if the heap is managed by the backend allocator.
        :param heap:
        :return:
        """
        log.debug('HEAP_get_frontend_chunks')
        if heap.FrontEndHeapType == 0:
            # Backend allocators, nothing to do with Frontend.
            raise TypeError('FrontEndHeapType says this is a backend heap')
        elif heap.FrontEndHeapType == 1:  # windows XP per default
            lal_free_c = self.get_lookaside_chunks(heap)
            return set(), lal_free_c
            # TODO committed ?
        elif heap.FrontEndHeapType == 2:  # win7 per default
            _c, _f = self.get_lfh_chunks(heap)
            # remove the unused parts
            allocs = set([(c[0], c[1]) for c in _c])
            return allocs, _f
        else:
            raise ValueError('FrontEndHeapType should be 0,1,2 not %d' % heap.FrontEndHeapType)

    def HEAP_getFreeLists_by_blocksindex(self, record):
        """ Understanding_the_LFH.pdf page 21
        Not Implemented yet
        """
        freeList = []
        # 128 blocks
        start = ctypes.addressof(record.BlocksIndex)
        bi_addr = self._utils.get_pointee_address(record.BlocksIndex)
        # enumerate BlocksIndex recursively on ExtendedLookup param
        while bi_addr != 0:
            log.debug('BLocksIndex is at %x' % (bi_addr))
            m = self._memory_handler.get_mapping_for_address(bi_addr)
            bi = m.read_struct(bi_addr, self.win_heap.HEAP_LIST_LOOKUP)
            """
                ('ExtendedLookup', POINTER(HEAP_LIST_LOOKUP)),
                ('ArraySize', __uint32_t),
                ('ExtraItem', __uint32_t),
                ('ItemCount', __uint32_t),
                ('OutOfRangeItems', __uint32_t),
                ('BaseIndex', __uint32_t),
                ('ListHead', POINTER(LIST_ENTRY)),
                ('ListsInUseUlong', POINTER(__uint32_t)),
                ('ListHints', POINTER(POINTER(LIST_ENTRY))),
            """
            log.debug('ArraySize is %d' % (bi.ArraySize))
            log.debug('BlocksIndex: %s' % (bi.to_string()))
            hints_addr = self._utils.get_pointee_address(bi.ListHints)
            log.debug('ListHints is pointing to %x' % (hints_addr))
            extlookup_addr = self._utils.get_pointee_address(bi.ExtendedLookup)
            log.debug('ExtendedLookup is pointing to %x' % (extlookup_addr))
            if extlookup_addr == 0:
                """ all chunks of size greater than or equal to BlocksIndex->ArraySize - 1 will
                be stored in ascending order in FreeList[ArraySize-BaseIndex – 1] """
                log.debug(
                    'Free chunks >= %d stored at FreeList[ArraySize(%d)-BaseIndex(%d) – 1]' %
                    (bi.ArraySize - 1, bi.ArraySize, bi.BaseIndex))
                #raise NotImplementedError()
            log.debug('-' * 80)
            bi_addr = extlookup_addr
        #
        raise NotImplementedError('NOT FINISHED')
        #raise StopIteration

    def HEAP_ENTRY_decode(self, chunk_header, heap):
        """returns a decoded copy of the HEAP_ENTRY/HEAP_FREE_ENTRY"""
        # 32 bits: struct__HEAP_ENTRY_0_0
        # 64 bits: struct__HEAP_ENTRY_0_0_0_0 (not aligned on offset 0)
        if self._target.get_cpu_bits() == 32:
            struct_type = self.win_heap.struct__HEAP_ENTRY_0_0
            heap_entry = chunk_header._0._0
            encoding = heap.Encoding._0._0
        elif self._target.get_cpu_bits() == 64:
            # Taking care of alignment issues on x64
            struct_type = self.win_heap.struct__HEAP_ENTRY_0_0_0_0
            heap_entry = chunk_header._0._0._1._0
            encoding = heap.Encoding._0._0._1._0
        else:
            raise NotImplementedError("Platform not supported")
        chunk_len = ctypes.sizeof(heap_entry)
        chunk_header_decoded = struct_type.from_buffer_copy(heap_entry)
        # decode the heap entry chunk header with the heap.Encoding
        working_array = (ctypes.c_ubyte * chunk_len).from_buffer(chunk_header_decoded)
        encoding_array = (ctypes.c_ubyte * chunk_len).from_buffer(encoding)
        # check if (heap.Encoding & working_array)
        if True:
            s = 0
            for i in range(chunk_len):
                s += working_array[i] & encoding_array[i]
            if s == 0:
                log.error('HEAP_ENTRY 0x%x NOT ENCODED || BUG: %s', chunk_header._orig_address_, hex(heap._orig_address_))
                return chunk_header_decoded
        # decode
        for i in range(chunk_len):
            working_array[i] ^= encoding_array[i]
        return chunk_header_decoded

    def HEAP_get_freelists(self, record):
        """Returns the list of free chunks.

        Understanding_the_LFH.pdf page 18 ++
        We iterate on HEAP.FreeLists to get ALL free blocks.

        @returns freeblock_addr : the address of the HEAP_ENTRY (chunk header)
            size : the size of the free chunk + HEAP_ENTRY header size, in blocks.
        """
        res = list()
        for freeblock in self.iterate_list_from_field(record, 'FreeLists'):
            # freeblock is typed with the linked list type, we need the root type
            # HEAP_FREE_ENTRY and HEAP_ENTRY have the same layout. Simplification.
            # freeblock2 = self.win_heap.HEAP_FREE_ENTRY.from_buffer(freeblock)
            freeblock2 = self.win_heap.HEAP_ENTRY.from_buffer(freeblock)
            if record.EncodeFlagMask:
                chunk_header = self.HEAP_ENTRY_decode(freeblock2, record)
            else:
                # TODO? winxp ?
                chunk_header = freeblock2._0._0 # 32b
            # size = header + freespace
            res.append((freeblock._orig_address_, chunk_header.Size * self._word_size_x2))
        return res

    def UNUSED_get_chunk(self, entry_addr):
        m = self._memory_handler.get_mapping_for_address(entry_addr)
        chunk_header = m.read_struct(entry_addr, self.win_heap.HEAP_ENTRY)
        self._memory_handler.keepRef(chunk_header, self.win_heap.HEAP_ENTRY, entry_addr)
        # FIXME what is this hack
        chunk_header._orig_address_ = entry_addr
        return chunk_header

    def print_heap_analysis(self, heap, verbose):
        addr = heap._orig_address_
        heap_not_at_start = ''
        m = self._memory_handler.get_mapping_for_address(addr)
        if addr != m.start:
            heap_not_at_start = ' (!) '

        print '[+] %sHEAP:0x%0.8x' % (heap_not_at_start, addr), m
        if not verbose:
            return
        #
        print '    FrontEndHeapType:', heap.FrontEndHeapType, FrontEndHeapType.get(heap.FrontEndHeapType, 'UNKNOWN')

        finder = self._memory_handler.get_heap_finder()
        walker = finder.get_heap_walker(m)
        ucrs = self.print_heap_analysis_details(heap)
        self.print_segments_analysis(heap, walker, ucrs)
        self.print_frontend_analysis_details(heap)

    def print_heap_analysis_details(self, heap):
        # check counters, sizes...
        # show UCR ranges at heap levels,
        # win7: UCRList
        # winxp: UnusedUCR, UCRSegments
        raise NotImplementedError()

    def print_frontend_analysis_details(self, heap):
        raise NotImplementedError()

    def print_segments_analysis(self, heap, walker, ucrs):
        # show segments details
        raise NotImplementedError()

    def print_mapping_children_analysis(self, heap):
        # look at children from free/allocations POV
        addr = heap._orig_address_
        m = self._memory_handler.get_mapping_for_address(addr)
        print '[+] ', m
        finder = self._memory_handler.get_heap_finder()
        walker = finder.get_heap_walker(m)
        children = walker.get_heap_children_mmaps()

        # get allocated/free stats by mappings
        overhead_size = self._memory_handler.get_target_platform().get_target_ctypes().sizeof(self.win_heap.struct__HEAP_ENTRY)
        occupied_res = self.count_by_mapping(walker.get_user_allocations(), overhead_size)
        free_res = self.count_by_mapping(walker.get_free_chunks(), overhead_size)

        allocated, allocated_overhead = occupied_res.get(m, (0, 0))
        free, free_overhead = free_res.get(m, (0, 0))
        overhead = allocated_overhead + free_overhead
        sum_ = allocated + free + overhead
        print "\ta:0x%0.8x \tf:0x%0.8x \to:0x%0.8x Sum:0x%0.8x" % (allocated, free, overhead, sum_)
        for child in children:
            print '\t[-] ', child
            allocated, allocated_overhead = occupied_res.get(child, (0, 0))
            free, free_overhead = free_res.get(child, (0, 0))
            overhead = allocated_overhead + free_overhead
            sum_ = allocated + free + overhead
            print "\ta:0x%0.8x \tf:0x%0.8x \to:0x%0.8x Sum:0x%0.8x" % (allocated, free, overhead, sum_)
        return

    def count_by_mapping(self, chunksize_tuple, overhead_size):
        res = {}
        for addr, size in chunksize_tuple:
            m = self._memory_handler.get_mapping_for_address(addr)
            if m not in res:
                # (size,overhead)
                res[m] = (0, 0)
            tsize, overhead = res[m]
            tsize += size
            overhead += overhead_size # size of win chunk header
            res[m] = (tsize, overhead)
        return res

    def count_by_segment(self, segment_list, chunksize_tuple, overhead_size):
        # change segments_list to [(start,end)]
        res = {}
        for addr, size in chunksize_tuple:
            for s in segment_list:
                start = self._utils.get_pointee_address(s.FirstEntry)
                end = self._utils.get_pointee_address(s.LastValidEntry)
                if start <= addr <= end:
                    # we found the segment
                    key = start
                    if key not in res:
                        # (size,overhead)
                        res[key] = (0, 0)
                    tsize, overhead = res[key]
                    tsize += size
                    overhead += overhead_size # size of win chunk header
                    res[key] = (tsize, overhead)
                    break
        return res
