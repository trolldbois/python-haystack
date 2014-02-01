#!/usr/bin/env python
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
from haystack import model
from haystack import utils
from haystack import constraints

from haystack.reverse.win32 import win7heap_generated as gen

import ctypes
import struct
import logging
import sys

import code

log = logging.getLogger('win7heap')

################ START copy generated classes ##########################
# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])
# register all classes to haystack
# create plain old python object from ctypes.Structure's, to pickle them
model.registerModule(sys.modules[__name__])
################ END copy generated classes ############################


############# Start expectedValues and methods overrides #################

## fix partial declaration
_HEAP_LOCK._fields_ = [
    ('voidme', ctypes.c_ubyte),
    ]

_LFH_BLOCK_ZONE._fields_ = [
    ('voidme', ctypes.c_ubyte),
    ]


## HEAP_SEGMENT

_HEAP_SEGMENT.expectedValues = {
    'SegmentSignature':[0xffeeffee],
    # Ignore the LastValidEntry pointer. It sometimes points to UCR (unmmaped)
    'LastValidEntry': constraints.IgnoreMember,
}

#_HEAP_SEGMENT.UCRSegmentList. points to _HEAP_UCR_DESCRIPTOR.SegmentEntry.
#_HEAP_UCR_DESCRIPTOR.SegmentEntry. points to _HEAP_SEGMENT.UCRSegmentList.

_HEAP_SEGMENT._listHead_ = [ 
                     ('UCRSegmentList', _HEAP_UCR_DESCRIPTOR, 'ListEntry', -8)]

#_HEAP_UCR_DESCRIPTOR._listHead_ = [ ('SegmentEntry', _HEAP_SEGMENT, 'Entry')]


# HEAP_ENTRY
# SubSegmentCode is a encoded c_void_p
# FIXME: is valid should decode it for validation ?
N11_HEAP_ENTRY3DOT_13DOT_3E.expectedValues = {
    'SubSegmentCode': constraints.IgnoreMember,
    }


def _HEAP_SEGMENT_get_UCR_segment_list(self, mappings):
    """Returns a list of UCR segments for this segment.
    HEAP_SEGMENT.UCRSegmentList is a linked list to UCRs for this segment.
    Some may have Size == 0.
    """
    ucrs = list()
    for ucr in self.iterateListField(mappings, 'UCRSegmentList'):
        ucr_struct_addr = ucr._orig_address_
        ucr_addr = utils.get_pointee_address(ucr.Address)
        # UCR.Size are not chunks sizes. NOT *8
        log.debug("Segment.UCRSegmentList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x"%(
                   ucr_struct_addr, ucr_addr, ucr.Size))
        ucrs.append(ucr)
    return ucrs

_HEAP_SEGMENT.get_UCR_segment_list = _HEAP_SEGMENT_get_UCR_segment_list

###### HEAP

#HEAP CommitRoutine encoded by a global key
#The HEAP handle data structure includes a function pointer field called 
#CommitRoutine that is called when memory regions within the heap are committed.
#Starting with Windows Vista, this field was encoded using a random value that 
#was also stored as a field in the HEAP handle data structure.

_HEAP.expectedValues = {
    'Signature':[0xeeffeeff],
    'FrontEndHeapType': [0,1,2],
    'CommitRoutine': constraints.IgnoreMember,
}
_HEAP._listHead_ = [('SegmentList', _HEAP_SEGMENT, 'SegmentListEntry', -16 ),
                    ('UCRList', _HEAP_UCR_DESCRIPTOR, 'ListEntry', 0 ),
                    # for get_freelists. offset is sizeof(HEAP_ENTRY)
                    ('FreeLists', _HEAP_FREE_ENTRY, 'FreeList', -8), 
                    ('VirtualAllocdBlocks', _HEAP_VIRTUAL_ALLOC_ENTRY, 'Entry', -8 )]
#HEAP.SegmentList. points to SEGMENT.SegmentListEntry.
#SEGMENT.SegmentListEntry. points to HEAP.SegmentList.
# you need to ignore the Head in the iterator...

def _HEAP_get_virtual_allocated_blocks_list(self, mappings):
    """Returns a list of virtual allocated entries.
    
    TODO: need some working on.
    """
    vallocs = list()
    for valloc in self.iterateListField(mappings, 'VirtualAllocdBlocks'):
        vallocs.append(valloc)
        log.debug("vallocBlock: @0x%0.8x commit: 0x%x reserved: 0x%x"%(
                   valloc._orig_address_, valloc.CommitSize, valloc.ReserveSize))
    return vallocs

_HEAP.get_virtual_allocated_blocks_list = _HEAP_get_virtual_allocated_blocks_list


def _HEAP_get_free_UCR_segment_list(self, mappings):
    """Returns a list of available UCR segments for this heap.
    HEAP.UCRList is a linked list to all UCRSegments
    
    """
    # TODO: exclude UCR segment from valid pointer values in mappings.
    ucrs = list()
    for ucr in self.iterateListField(mappings, 'UCRList'):
        ucr_struct_addr = ucr._orig_address_
        ucr_addr = utils.get_pointee_address(ucr.Address)
        # UCR.Size are not chunks sizes. NOT *8
        log.debug("Heap.UCRList: 0x%0.8x addr: 0x%0.8x size: 0x%0.5x"%(
                   ucr_struct_addr, ucr_addr, ucr.Size))
        ucrs.append(ucr)
    return ucrs

_HEAP.get_free_UCR_segment_list = _HEAP_get_free_UCR_segment_list


def _HEAP_get_segment_list(self, mappings):
    """returns a list of all segment attached to one Heap structure."""
    segments = list()
    for segment in self.iterateListField(mappings, 'SegmentList'):
        segment_addr = segment._orig_address_
        first_addr = utils.get_pointee_address(segment.FirstEntry)
        last_addr = utils.get_pointee_address(segment.LastValidEntry)
        log.debug( 'Heap.Segment: 0x%0.8x FirstEntry: 0x%0.8x LastValidEntry: 0x%0.8x'%( segment_addr, first_addr, last_addr) )
        segments.append(segment)
    return segments
    

_HEAP.get_segment_list = _HEAP_get_segment_list

def _HEAP_get_chunks(self, mappings):
    """Returns a list of tuple(address,size) for all chunks in
     the backend allocator."""
    allocated = list()
    free = list()
    for segment in self.get_segment_list(mappings):
        first_addr = utils.get_pointee_address(segment.FirstEntry)
        last_addr = utils.get_pointee_address(segment.LastValidEntry)
        # create the skip list for each segment.
        skiplist = dict()
        for ucr in segment.get_UCR_segment_list(mappings):
            ucr_addr = utils.get_pointee_address(ucr.Address)
            skiplist[ucr_addr] = ucr.Size # UCR.Size are not chunks sizes. NOT *8
        #
        chunk_addr = first_addr
        while (chunk_addr < last_addr):
            if chunk_addr in skiplist:
                size = skiplist[chunk_addr]
                log.debug('Skipping 0x%0.8x - skip %0.5x bytes to 0x%0.8x'%(chunk_addr, size, chunk_addr+size))
                chunk_addr += size
                continue
            chunk_header = mappings.getRef(_HEAP_ENTRY, chunk_addr)
            if chunk_header is None: # force read it
                chunk_header = _get_chunk(mappings, self, chunk_addr)
            if self.EncodeFlagMask: #heap.EncodeFlagMask
                chunk_header = _HEAP_ENTRY_decode(chunk_header, self)
            #log.debug('\t\tEntry: 0x%0.8x\n%s'%( chunk_addr, chunk_header))
            
            if ((chunk_header.Flags & 1) == 1):
                log.debug('Chunk 0x%0.8x is in use size: %0.5x'%(chunk_addr, chunk_header.Size*8))
                allocated.append( (chunk_addr, chunk_header.Size*8) )
            else:
                log.debug('Chunk 0x%0.8x is FREE'%(chunk_addr))
                free.append( (chunk_addr, chunk_header.Size*8) )
                pass
            chunk_addr += chunk_header.Size*8
    return (allocated, free)

_HEAP.get_chunks = _HEAP_get_chunks


def _HEAP_get_frontend_chunks(self, mappings):
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
    log.debug('_HEAP_get_frontend_chunks')
    ptr = self.FrontEndHeap
    addr = utils.get_pointee_address(ptr)
    if self.FrontEndHeapType == 1: # windows XP per default
        ## TODO delete this ptr from the heap-segment entries chunks
        for x in range(128):
            log.debug('finding lookaside %d at @%x'%(x, addr))
            m = mappings.getMmapForAddr(addr)
            st = m.readStruct(addr, _HEAP_LOOKASIDE)
            # load members on self.FrontEndHeap car c'est un void *
            for free in st.iterateList('ListHead'): # single link list.
                ## TODO delete this free from the heap-segment entries chunks
                log.debug('free')
                res.append( free ) #???
                pass
            addr += ctypes.sizeof(_HEAP_LOOKASIDE)
    elif self.FrontEndHeapType == 2: # win7 per default
        log.debug('finding frontend at @%x'%(addr))
        m = mappings.getMmapForAddr(addr)
        st = m.readStruct(addr, _LFH_HEAP)
        # LFH is a big chunk allocated by the backend allocator, called subsegment
        # but rechopped as small chunks of a heapbin.
        # Active subsegment hold that big chunk.
        #
        #
        # load members on self.FrontEndHeap car c'est un void *
        if not st.loadMembers(mappings, 1):
            log.error('Error on loading frontend')
            raise model.NotValid('Frontend load at @%x is not valid'%(addr))
        
        #log.debug(st.LocalData[0].toString())
        #
        for sinfo in st.LocalData[0].SegmentInfo: #### 128 _HEAP_LOCAL_SEGMENT_INFO
            # TODO , what about ActiveSubsegment ?
            for items_ptr in sinfo.CachedItems: # 16 caches items max
                items_addr = utils.get_pointee_address(items_ptr)
                if not bool(items_addr):
                    #log.debug('NULL pointer items')
                    continue
                m = mappings.getMmapForAddr(items_addr)
                subsegment = m.readStruct( items_addr, _HEAP_SUBSEGMENT)
                #log.debug(subsegment)
                ## TODO current subsegment.SFreeListEntry is on error at some depth.
                ## bad pointer value on the second subsegment
                chunks = subsegment.get_userblocks()
                free = subsegment.get_freeblocks()
                committed = set(chunks) - set(free)
                all_free.extend(free)
                all_committed.extend( committed ) 
                log.debug('subseg: 0x%0.8x, commit: %d chunks free: %d chunks'%(items_addr, len(committed), len(free) ))
    else:
        #print 'FrontEndHeapType == %d'%(self.FrontEndHeapType)
        #raise StopIteration
        pass
    return all_committed, all_free
    
_HEAP.get_frontend_chunks = _HEAP_get_frontend_chunks

############################## HEAP_SUBSEGMENT

def _HEAP_SUBSEGMENT_get_userblocks(self):
    """
    AggregateExchg contains info on userblocks, number left, depth
    
    """
    userblocks_addr = utils.get_pointee_address(self.UserBlocks)
    if not bool(userblocks_addr):
        log.debug('Userblocks is null')
        return []
    # its basically an array of self.BlockCount blocks of self.BlockSie*8 bytes.
    log.debug('fetching %d blocks of %d bytes'%(self.BlockCount, self.BlockSize*8))
    # UserBlocks points to _HEAP_USERDATA_HEADER. Real user data blocks will starts after sizeof( _HEAP_USERDATA_HEADER ) = 0x10
    # each chunk starts with a 8 byte header + n user-writeable data
    # user writable chunk starts with 2 bytes for next offset
    # basically, first committed block is first.
    # ( page 38 ) 
    userblocks = [ (userblocks_addr + 0x10 + self.BlockSize*8*i, self.BlockSize*8) for i in range(self.BlockCount)]
    #
    ## we need to substract non allocated blocks
    # self.AggregateExchg.Depth counts how many blocks are remaining free
    # if self.AggregateExchg.FreeEntryOffset == 0x2, there a are no commited blocks
    return userblocks 


def _HEAP_SUBSEGMENT_get_freeblocks(self):
    """
    Use AggregateExchg.Depth and NextFreeoffset to fetch the head, then traverse the links
    """
    userblocks_addr = utils.get_pointee_address(self.UserBlocks)
    if not bool(userblocks_addr):
        return []
    if self.AggregateExchg.FreeEntryOffset == 0x2 :
        log.debug(' * FirstFreeOffset==0x2 Depth==%d'%(self.AggregateExchg.Depth))
    # self.AggregateExchg.Depth the size of UserBlock divided by the HeapBucket size
    # self.AggregateExchg.FreeEntryOffset starts at 0x2 (blocks), which means 0x10 bytes after UserBlocks
    # see Understanding LFH page 14
    # nextoffset of user data is at current + offset*8 + len(HEAP_ENTRY)
    freeblocks = [ (userblocks_addr + (self.AggregateExchg.FreeEntryOffset*8) + self.BlockSize*8*i, self.BlockSize*8) for i in range(self.AggregateExchg.Depth)]
    return freeblocks
    ###
        
    #ptr = utils.get_pointee_address(self.AggregateExchg.FreeEntryOffset)
    #for i in range(self.AggregateExchg.Depth):
    #    free.append( userBlocks+ 8*ptr)
    #    ## ptr = m.readWord( userBlocks+ 8*ptr+8 ) ?????
    #return blocks 
    
    
    #free = []
    #ptr = subseg.FreeEntryOffset
    #subseg.depth.times { 
    #    free << (up + 8*ptr)
    #    ptr = @dbg.memory[up + 8*ptr + 8, 2].unpack('v')[0]
    #}
    #@foo ||= 0
    #@foo += 1
    #p @foo if @foo % 10 == 0#
    #
    #up += 0x10
    #list -= free
    #list.each { |p| @chunks[p+8] = bs*8 - (@cp.decode_c_struct('_HEAP_ENTRY', @dbg.memory, p).unusedbytes & 0x7f) }
    #end

_HEAP_SUBSEGMENT.get_userblocks = _HEAP_SUBSEGMENT_get_userblocks
_HEAP_SUBSEGMENT.get_freeblocks = _HEAP_SUBSEGMENT_get_freeblocks

#### HEAP_UCR_DESCRIPTOR
#_HEAP_UCR_DESCRIPTOR._listMember_ = ['ListEntry']
#_HEAP_UCR_DESCRIPTOR._listHead_ = [    ('SegmentEntry', _HEAP_SEGMENT, 'SegmentListEntry'),    ]

# per definition, reserved space is not maped.
HEAP_UCR_DESCRIPTOR.expectedValues = {
    'Address': constraints.IgnoreMember,
}

#### _HEAP_LOCAL_SEGMENT_INFO
# _HEAP_LOCAL_SEGMENT_INFO.LocalData should be a pointer, but the values are small ints ?
# _HEAP_LOCAL_SEGMENT_INFO.LocalData == 0x3 ?
_HEAP_LOCAL_SEGMENT_INFO.expectedValues = {
    'LocalData': constraints.IgnoreMember,
}



## TODO current subsegment.SFreeListEntry is on error at some depth.
## bad pointer value on the second subsegment
_HEAP_SUBSEGMENT.expectedValues = {
    'SFreeListEntry': constraints.IgnoreMember,
}








def _HEAP_getFreeLists_by_blocksindex(self, mappings):
    """ Understanding_the_LFH.pdf page 21 
    Not Implemented yet
    """
    freeList = []
    # 128 blocks
    start = ctypes.addressof(self.BlocksIndex) 
    bi_addr = utils.get_pointee_address(self.BlocksIndex)
    # enumerate BlocksIndex recursively on ExtendedLookup param
    while bi_addr != 0:
        log.debug('BLocksIndex is at %x'%(bi_addr))
        m = mappings.getMmapForAddr(bi_addr)
        bi = m.readStruct( bi_addr, _HEAP_LIST_LOOKUP)
        """
            ('ExtendedLookup', POINTER(_HEAP_LIST_LOOKUP)),
            ('ArraySize', __uint32_t),
            ('ExtraItem', __uint32_t),
            ('ItemCount', __uint32_t),
            ('OutOfRangeItems', __uint32_t),
            ('BaseIndex', __uint32_t),
            ('ListHead', POINTER(_LIST_ENTRY)),
            ('ListsInUseUlong', POINTER(__uint32_t)),
            ('ListHints', POINTER(POINTER(_LIST_ENTRY))),
        """
        log.debug('ArraySize is %d'%(bi.ArraySize))        
        log.debug('BlocksIndex: %s'%(bi.toString()))        
        hints_addr = utils.get_pointee_address(bi.ListHints)
        log.debug('ListHints is pointing to %x'%(hints_addr))
        extlookup_addr = utils.get_pointee_address(bi.ExtendedLookup)
        log.debug('ExtendedLookup is pointing to %x'%(extlookup_addr))
        if extlookup_addr == 0:
            """ all chunks of size greater than or equal to BlocksIndex->ArraySize - 1 will 
            be stored in ascending order in FreeList[ArraySize-BaseIndex – 1] """
            log.debug('Free chunks >= %d stored at FreeList[ArraySize(%d)-BaseIndex(%d) – 1]'%(bi.ArraySize-1, bi.ArraySize, bi.BaseIndex))
            #raise NotImplementedError()
        log.debug('-'*80)
        bi_addr = extlookup_addr
    # 
    raise NotImplementedError('NOT FINISHED')
    raise StopIteration


def _HEAP_ENTRY_decode(chunk_header, heap):
    """returns a decoded copy """
    #N11_HEAP_ENTRY3DOT_13DOT_2E()
    chunk_len = ctypes.sizeof(N11_HEAP_ENTRY3DOT_13DOT_2E)
    chunk_header_decoded = (N11_HEAP_ENTRY3DOT_13DOT_2E).from_buffer_copy(chunk_header)
    working_array = (ctypes.c_ubyte*chunk_len).from_buffer(chunk_header_decoded)
    encoding_array = (ctypes.c_ubyte*chunk_len).from_buffer_copy(heap.Encoding)
    # check if (heap.Encoding & working_array)
    s = 0
    for i in range(chunk_len):
        s += working_array[i] & encoding_array[i]
    #if s == 0: #DEBUG TODO
    #    print 'NOT ENCODED !!!',hex(ctypes.addressof(heap))
    #    return chunk_header
    for i in range(chunk_len):
        working_array[i] ^= encoding_array[i]
    return chunk_header_decoded

_HEAP_ENTRY.decode = _HEAP_ENTRY_decode
def _get_chunk(mappings, heap, entry_addr):
    m = mappings.getMmapForAddr(entry_addr)
    chunk_header = m.readStruct( entry_addr, _HEAP_ENTRY)
    mappings.keepRef( chunk_header, _HEAP_ENTRY, entry_addr)
    chunk_header._orig_address_ = entry_addr
    return chunk_header

def _HEAP_get_freelists(self, mappings):
    """Returns the list of free chunks.
    
    This method is very important because its used by memory_mappings to 
    load mappings that contains subsegment of a heap.
    
    Understanding_the_LFH.pdf page 18 ++
    We iterate on _HEAP.FreeLists to get ALL free blocks.
    
    @returns freeblock_addr : the address of the _HEAP_ENTRY (chunk header)
        size : the size of the free chunk + _HEAP_ENTRY header size, in blocks.
    """
    # FIXME: we should use get_segmentlist to coallescce segment in one heap
    # memory mapping. Not free chunks.
    res = list()
    for freeblock in self.iterateListField( mappings, 'FreeLists'):
        if self.EncodeFlagMask:
            chunk_header = _HEAP_ENTRY_decode(freeblock, self)
        # size = header + freespace
        res.append( (freeblock._orig_address_, chunk_header.Size*8))
    return res
    
_HEAP.get_freelists = _HEAP_get_freelists

#def _HEAP_getFreeListsWinXP(self, mappings):
# Understanding_the_LFH.pdf page 17 """



########## _LIST_ENTRY

from haystack import listmodel
listmodel.declare_double_linked_list_type(_LIST_ENTRY, 'FLink', 'BLink')









