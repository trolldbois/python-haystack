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
from haystack import listmodel



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

class Win7HeapValidator(listmodel.ListModel):

    def __init__(self, memory_handler, my_constraints, win7heap_module):
        super(Win7HeapValidator, self).__init__(memory_handler, my_constraints)
        self.win7heap = win7heap_module
        # LIST_ENTRY
        listmodel.declare_double_linked_list_type(self._ctypes, self.win7heap.LIST_ENTRY, 'Flink', 'Blink')

        # HEAP_SEGMENT
        # HEAP_SEGMENT.UCRSegmentList. points to HEAP_UCR_DESCRIPTOR.SegmentEntry.
        # HEAP_UCR_DESCRIPTOR.SegmentEntry. points to HEAP_SEGMENT.UCRSegmentList.
        # FIXME, use offset size base on self._target.get_word_size()
        self.register_list_field_and_type(self.win7heap.HEAP_SEGMENT, 'UCRSegmentList', self.win7heap.HEAP_UCR_DESCRIPTOR, 'ListEntry', -8)
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
        self.register_list_field_and_type(self.win7heap.HEAP, 'SegmentList', self.win7heap.HEAP_SEGMENT, 'SegmentListEntry', -16)
        self.register_list_field_and_type(self.win7heap.HEAP, 'UCRList', self.win7heap.HEAP_UCR_DESCRIPTOR, 'ListEntry', 0)
        # for get_freelists. offset is sizeof(HEAP_ENTRY)
        self.register_list_field_and_type(self.win7heap.HEAP, 'FreeLists', self.win7heap.HEAP_FREE_ENTRY, 'FreeList', -8)
        self.register_list_field_and_type(self.win7heap.HEAP, 'VirtualAllocdBlocks', self.win7heap.HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8)

        # HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
        # SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
        # you need to ignore the Head in the iterator...

        # HEAP_UCR_DESCRIPTOR
        #HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
        #HEAP_UCR_DESCRIPTOR._listHead_ = [    ('SegmentEntry', HEAP_SEGMENT, 'SegmentListEntry'),    ]

    def HEAP_SEGMENT_get_UCR_segment_list(self):
        """Returns a list of UCR segments for this segment.
        HEAP_SEGMENT.UCRSegmentList is a linked list to UCRs for this segment.
        Some may have Size == 0.
        """
        ucrs = list()
        self._utils = self._memory_handler.get_ctypes_utils()
        for ucr in self.iterate_list_field(self._memory_handler, 'UCRSegmentList'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    # HEAP
    def HEAP_get_virtual_allocated_blocks_list(self, record):
        """Returns a list of virtual allocated entries.

        TODO: need some working on.
        """
        vallocs = list()
        for valloc in self.iterate_list_field(record, 'VirtualAllocdBlocks'):
            vallocs.append(valloc)
            log.debug("vallocBlock: @0x%0.8x commit: 0x%x reserved: 0x%x" % (
                valloc._orig_address_, valloc.CommitSize, valloc.ReserveSize))
        return vallocs

    def HEAP_get_free_UCR_segment_list(self, record):
        """Returns a list of available UCR segments for this heap.
        HEAP.UCRList is a linked list to all UCRSegments

        """
        # TODO: exclude UCR segment from valid pointer values in _memory_handler.
        ucrs = list()
        for ucr in self.iterate_list_field(record, 'UCRList'):
            ucr_struct_addr = ucr._orig_address_
            ucr_addr = self._utils.get_pointee_address(ucr.Address)
            # UCR.Size are not chunks sizes. NOT *8
            log.debug("Heap.UCRList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x" % (
                ucr_struct_addr, ucr_addr, ucr.Size))
            ucrs.append(ucr)
        return ucrs

    def HEAP_get_segment_list(self, record):
        """returns a list of all segment attached to one Heap structure."""
        segments = list()
        for segment in self.iterate_list_field(record, 'SegmentList'):
            segment_addr = segment._orig_address_
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            log.debug(
                'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x' %
                (segment_addr, first_addr, last_addr))
            segments.append(segment)
        return segments

    def HEAP_get_chunks(self, record):
        """Returns a list of tuple(address,size) for all chunks in
         the backend allocator."""
        allocated = list()
        free = list()
        for segment in self.HEAP_get_segment_list(record):
            first_addr = self._utils.get_pointee_address(segment.FirstEntry)
            last_addr = self._utils.get_pointee_address(segment.LastValidEntry)
            # create the skip list for each segment.
            skiplist = dict()
            for ucr in segment.get_UCR_segment_list(record):
                ucr_addr = self._utils.get_pointee_address(ucr.Address)
                # UCR.Size are not chunks sizes. NOT *8
                skiplist[ucr_addr] = ucr.Size
            #
            chunk_addr = first_addr
            while (chunk_addr < last_addr):
                if chunk_addr in skiplist:
                    size = skiplist[chunk_addr]
                    log.debug(
                        'Skipping 0x%0.8x - skip %0.5x bytes to 0x%0.8x' %
                        (chunk_addr, size, chunk_addr + size))
                    chunk_addr += size
                    continue
                chunk_header = self._memory_handler.getRef(self.win7heap.HEAP_ENTRY, chunk_addr)
                if chunk_header is None:  # force read it
                    chunk_header = self._get_chunk(chunk_addr)
                if record.EncodeFlagMask:  # heap.EncodeFlagMask
                    chunk_header = self.HEAP_ENTRY_decode(chunk_header, record)
                #log.debug('\t\tEntry: 0x%0.8x\n%s'%( chunk_addr, chunk_header))

                if ((chunk_header.Flags & 1) == 1):
                    log.debug(
                        'Chunk 0x%0.8x is in use size: %0.5x' %
                        (chunk_addr, chunk_header.Size * 8))
                    allocated.append((chunk_addr, chunk_header.Size * 8))
                else:
                    log.debug('Chunk 0x%0.8x is FREE' % (chunk_addr))
                    free.append((chunk_addr, chunk_header.Size * 8))
                    pass
                chunk_addr += chunk_header.Size * 8
        return (allocated, free)

    def HEAP_get_frontend_chunks(self, record):
        """ windows xp ?
            the list of chunks from the frontend are deleted from the segment chunk list.

            Functionnaly, (page 28) LFH_HEAP should be fetched by HEAP_BUCKET calcul

        //position 0x7 in the header denotes
        //whether the chunk was allocated via
        //the front-end or the back-end (non-encoded ;) )
        if(ChunkHeader->UnusedBytes & 0x80)
            RtlpLowFragHeapFree
        else
            BackEndHeapFree

        """
        res = list()
        all_free = list()
        all_committed = list()
        log.debug('HEAP_get_frontend_chunks')
        ptr = record.FrontEndHeap
        addr = self._utils.get_pointee_address(ptr)
        if record.FrontEndHeapType == 1:  # windows XP per default
            # TODO delete this ptr from the heap-segment entries chunks
            for x in range(128):
                log.debug('finding lookaside %d at @%x' % (x, addr))
                m = self._memory_handler.get_mapping_for_address(addr)
                st = m.read_struct(addr, self.win7heap.HEAP_LOOKASIDE)
                # load members on self.FrontEndHeap car c'est un void *
                for free in st.iterateList('ListHead'):  # single link list.
                    # TODO delete this free from the heap-segment entries chunks
                    log.debug('free')
                    res.append(free)  # ???
                    pass
                addr += ctypes.sizeof(self.win7heap.HEAP_LOOKASIDE)
        elif record.FrontEndHeapType == 2:  # win7 per default
            log.debug('finding frontend at @%x' % (addr))
            m = self._memory_handler.get_mapping_for_address(addr)
            st = m.read_struct(addr, self.win7heap.LFH_HEAP)
            # LFH is a big chunk allocated by the backend allocator, called subsegment
            # but rechopped as small chunks of a heapbin.
            # Active subsegment hold that big chunk.
            #
            #
            # load members on self.FrontEndHeap car c'est un void *
            if not self.load_members(st, 1):
                log.error('Error on loading frontend')
                raise model.NotValid('Frontend load at @%x is not valid', addr)

            # log.debug(st.LocalData[0].toString())
            #
            # 128 HEAP_LOCAL_SEGMENT_INFO
            for sinfo in st.LocalData[0].SegmentInfo:
                # TODO , what about ActiveSubsegment ?
                for items_ptr in sinfo.CachedItems:  # 16 caches items max
                    items_addr = self._utils.get_pointee_address(items_ptr)
                    if not bool(items_addr):
                        #log.debug('NULL pointer items')
                        continue
                    m = self._memory_handler.get_mapping_for_address(items_addr)
                    subsegment = m.read_struct(items_addr, self.win7heap.HEAP_SUBSEGMENT)
                    # log.debug(subsegment)
                    # TODO current subsegment.SFreeListEntry is on error at some depth.
                    # bad pointer value on the second subsegment
                    chunks = subsegment.get_userblocks(self._memory_handler)
                    free = subsegment.get_freeblocks(self._memory_handler)
                    committed = set(chunks) - set(free)
                    all_free.extend(free)
                    all_committed.extend(committed)
                    log.debug(
                        'subseg: 0x%0.8x, commit: %d chunks free: %d chunks' %
                        (items_addr, len(committed), len(free)))
        else:
            # print 'FrontEndHeapType == %d'%(self.FrontEndHeapType)
            #raise StopIteration
            pass
        return all_committed, all_free

    # HEAP_SUBSEGMENT
    def HEAP_SUBSEGMENT_get_userblocks(self, record):
        """
        AggregateExchg contains info on userblocks, number left, depth
        """
        userblocks_addr = self._utils.get_pointee_address(record.UserBlocks)
        if not bool(userblocks_addr):
            log.debug('Userblocks is null')
            return []
        # the structure is astructure in an unnamed union of self
        st = record._3._0
        # its basically an array of self.BlockCount blocks of self.BlockSize*8
        # bytes.
        log.debug(
            'fetching %d blocks of %d bytes' %
            (st.BlockCount, st.BlockSize * 8))
        # UserBlocks points to HEAP_USERDATA_HEADER. Real user data blocks will starts after sizeof( HEAP_USERDATA_HEADER ) = 0x10
        # each chunk starts with a 8 byte header + n user-writeable data
        # user writable chunk starts with 2 bytes for next offset
        # basically, first committed block is first.
        # ( page 38 )
        userblocks = [
            (userblocks_addr +
             0x10 +
             st.BlockSize *
             8 *
             i,
             st.BlockSize *
             8) for i in range(
                st.BlockCount)]
        #
        # we need to substract non allocated blocks
        # self.AggregateExchg.Depth counts how many blocks are remaining free
        # if self.AggregateExchg.FreeEntryOffset == 0x2, there a are no commited
        # blocks
        return userblocks

    def HEAP_SUBSEGMENT_get_freeblocks(self, record):
        """
        Use AggregateExchg.Depth and NextFreeoffset to fetch the head, then traverse the links
        """
        userblocks_addr = self._utils.get_pointee_address(record.UserBlocks)
        if not bool(userblocks_addr):
            return []
        # structure is in a structure in an union
        # struct_c__S__INTERLOCK_SEQ_Ua_Sa_0
        aggExchange = record.AggregateExchg._0._0
        if aggExchange.FreeEntryOffset == 0x2:
            log.debug(' * FirstFreeOffset==0x2 Depth==%d', aggExchange.Depth)
        # self.AggregateExchg.Depth the size of UserBlock divided by the HeapBucket size
        # self.AggregateExchg.FreeEntryOffset starts at 0x2 (blocks), which means 0x10 bytes after UserBlocks
        # see Understanding LFH page 14
        # nextoffset of user data is at current + offset*8 + len(HEAP_ENTRY)
        # the structure is astructure in an unnamed union of self
        st = record._3._0
        freeblocks = [(userblocks_addr +
                       (aggExchange.FreeEntryOffset *
                        8) +
                       st.BlockSize *
                       8 *
                       i, st.BlockSize *
                       8) for i in range(aggExchange.Depth)]
        return freeblocks
        ###

        #ptr = utils.get_pointee_address(self.AggregateExchg.FreeEntryOffset)
        # for i in range(self.AggregateExchg.Depth):
        #    free.append( userBlocks+ 8*ptr)
        #    ## ptr = m.readWord( userBlocks+ 8*ptr+8 ) ?????
        # return blocks

        #free = []
        #ptr = subseg.FreeEntryOffset
        # subseg.depth.times {
        #    free << (up + 8*ptr)
        #    ptr = @dbg.memory[up + 8*ptr + 8, 2].unpack('v')[0]
        #}
        #@foo ||= 0
        #@foo += 1
        #p @foo if @foo % 10 == 0#
        #
        #up += 0x10
        #list -= free
        # list.each { |p| @chunks[p+8] = bs*8 - (@cp.decode_c_struct('HEAP_ENTRY', @dbg.memory, p).unusedbytes & 0x7f) }
        # end

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
            bi = m.read_struct(bi_addr, self.win7heap.HEAP_LIST_LOOKUP)
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
            log.debug('BlocksIndex: %s' % (bi.toString()))
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
        """returns a decoded copy """
        # contains the Size
        # 32 bits: struct__HEAP_ENTRY_0_0
        # FIXME BUG, we need to use _0_0_0_0 for 64 bits, otherwise
        # we are reading bad data
        # 64 bits: struct__HEAP_ENTRY_0_0_0_0
        chunk_len = ctypes.sizeof(self.win7heap.struct__HEAP_ENTRY_0_0)
        chunk_header_decoded = (
            self.win7heap.struct__HEAP_ENTRY_0_0).from_buffer_copy(chunk_header)
        # decode the heap entry chunk header with the heap.Encoding
        working_array = (
            ctypes.c_ubyte *
            chunk_len).from_buffer(chunk_header_decoded)
        encoding_array = (
            ctypes.c_ubyte *
            chunk_len).from_buffer_copy(
            heap.Encoding)
        # check if (heap.Encoding & working_array)
        s = 0
        for i in range(chunk_len):
            s += working_array[i] & encoding_array[i]
        # if s == 0: #DEBUG TODO
        #    print 'NOT ENCODED !!!',hex(ctypes.addressof(heap))
        #    return chunk_header
        for i in range(chunk_len):
            working_array[i] ^= encoding_array[i]
        return chunk_header_decoded

    def _get_chunk(self, entry_addr):
        m = self._memory_handler.get_mapping_for_address(entry_addr)
        chunk_header = m.read_struct(entry_addr, self.win7heap.HEAP_ENTRY)
        self._memory_handler.keepRef(chunk_header, self.win7heap.HEAP_ENTRY, entry_addr)
        # FIXME what is this hack
        chunk_header._orig_address_ = entry_addr
        return chunk_header

    def HEAP_get_freelists(self, record):
        """Returns the list of free chunks.

        This method is very important because its used by memory_memory_handler to
        load _memory_handler that contains subsegment of a heap.

        Understanding_the_LFH.pdf page 18 ++
        We iterate on HEAP.FreeLists to get ALL free blocks.

        @returns freeblock_addr : the address of the HEAP_ENTRY (chunk header)
            size : the size of the free chunk + HEAP_ENTRY header size, in blocks.
        """
        # FIXME: we should use get_segmentlist to coallescce segment in one heap
        # memory mapping. Not free chunks.
        res = list()
        for freeblock in self.iterate_list_field(record, 'FreeLists'):
            if record.EncodeFlagMask:
                chunk_header = self.HEAP_ENTRY_decode(freeblock, record)
            # size = header + freespace
            # FIXME: possible undeclared/masked value
            # FIXME: use word_size from self._target
            res.append((freeblock._orig_address_, chunk_header.Size * 8))
        return res


#HEAP_SEGMENT.get_UCR_segment_list = HEAP_SEGMENT_get_UCR_segment_list
#HEAP.get_virtual_allocated_blocks_list = HEAP_get_virtual_allocated_blocks_list
#HEAP.get_free_UCR_segment_list = HEAP_get_free_UCR_segment_list
#HEAP.get_segment_list = HEAP_get_segment_list
#HEAP.get_chunks = HEAP_get_chunks
#HEAP.get_frontend_chunks = HEAP_get_frontend_chunks
#HEAP_SUBSEGMENT.get_userblocks = HEAP_SUBSEGMENT_get_userblocks
#HEAP_SUBSEGMENT.get_freeblocks = HEAP_SUBSEGMENT_get_freeblocks
#HEAP_ENTRY.decode = HEAP_ENTRY_decode
#HEAP.get_freelists = HEAP_get_freelists
