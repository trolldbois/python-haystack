#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import struct
import operator
import os
import unittest
import pickle
import sys

from haystack import model
from haystack import types
from haystack import utils
from haystack import dump_loader

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger('testwin7heap')

class TestWin7Heap(unittest.TestCase):
    
    
    def setUp(self):
        model.reset()
        self._mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
        self._known_heaps = [(0x390000, 0x3000),  (0x540000, 0x1000),
                             (0x580000, 0x9000),  (0x5c0000, 0x59000),
                             (0x1ef0000, 0x1000), (0x2010000, 0x21000),
                             (0x2080000, 0x10000),(0x21f0000, 0x6000),
                             (0x3360000, 0x1000), (0x4030000, 0x1000),
                             (0x4110000, 0x1000), (0x41c0000, 0x1000),
                            ]
        return
        
    def tearDown(self):
        model.reset()
        self._mappings = None        
        return

    def test_ctypes_sizes(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap

        ctypes = self._mappings.config.ctypes
        print ctypes
        
        self.assertEquals(ctypes.sizeof(win7heap._HEAP_SEGMENT), 64)
        self.assertEquals(ctypes.sizeof(win7heap._HEAP_ENTRY), 8)
        self.assertEquals(ctypes.sizeof(ctypes.POINTER(None)), 4)
        self.assertEquals(ctypes.sizeof(
                                   ctypes.POINTER(win7heap._HEAP_TAG_ENTRY)), 4)
        self.assertEquals(ctypes.sizeof(win7heap._LIST_ENTRY), 8)
        self.assertEquals(ctypes.sizeof(
                                 ctypes.POINTER(win7heap._HEAP_LIST_LOOKUP)), 4)
        self.assertEquals(ctypes.sizeof(
                            ctypes.POINTER(win7heap._HEAP_PSEUDO_TAG_ENTRY)), 4)
        self.assertEquals(ctypes.sizeof(ctypes.POINTER(win7heap._HEAP_LOCK)), 4)
        self.assertEquals(ctypes.sizeof(ctypes.c_ubyte), 1 )
        self.assertEquals(ctypes.sizeof((ctypes.c_ubyte*1)), 1 )
        self.assertEquals(ctypes.sizeof(win7heap._HEAP_COUNTERS), 84 )
        self.assertEquals(ctypes.sizeof(win7heap._HEAP_TUNING_PARAMETERS), 8 )

        self.assertEquals(ctypes.sizeof(win7heap.HEAP ) , 312 )
        self.assertEquals(utils.offsetof(win7heap.HEAP , 'Signature') , 100 )


    def test_is_heap(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        h = self._mappings.get_mapping_for_address(0x005c0000)
        self.assertEquals(h.getByteBuffer()[0:10],
                        '\xc7\xf52\xbc\xc9\xaa\x00\x01\xee\xff')
        addr = h.start
        self.assertEquals( addr , 6029312)
        heap = h.readStruct( addr, win7heap.HEAP )
        
        # check that haystack memory_mapping works
        self.assertEquals(ctypes.addressof(h._local_mmap_content), 
                                                         ctypes.addressof(heap))
        # check heap.Signature
        self.assertEquals(heap.Signature, 4009750271L ) # 0xeeffeeff
        load = heap.loadMembers(self._mappings, 10)
        walker = win7heapwalker.Win7HeapFinder()
        self.assertTrue(walker.is_heap(self._mappings, h))

        
    def test_is_heap_all(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        walker = win7heapwalker.Win7HeapFinder()
        for addr, size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            # check heap.Signature
            self.assertEquals( heap.Signature , 4009750271L ) # 0xeeffeeff
            load = heap.loadMembers(self._mappings, 10)
            self.assertTrue(walker.is_heap(self._mappings, h))
        
        heaps = [(h.start, len(h)) for h in self._mappings.get_heaps()]
        heaps.sort()
        self.assertEquals(heaps, self._known_heaps)
        self.assertEquals(len(heaps), len(self._known_heaps))
        

    def test_get_UCR_segment_list(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        ucrs = heap.get_free_UCR_segment_list(self._mappings)
        self.assertEquals(heap.UCRIndex.value, 0x5c0590)
        self.assertEquals(heap.Counters.TotalUCRs, 1)
        # in this example, there is one UCR in 1 segment.
        self.assertEquals(len(ucrs), heap.Counters.TotalUCRs)
        ucr = ucrs[0]
        # UCR will point to non-mapped space. But reserved address space.
        self.assertEquals(ucr.Address.value,0x6b1000) 
        self.assertEquals(ucr.Size,0xf000) # bytes
        self.assertEquals(ucr.Address.value+ucr.Size,0x6c0000) 
        # check numbers.
        reserved_size = heap.Counters.TotalMemoryReserved
        committed_size = heap.Counters.TotalMemoryCommitted
        ucr_size = reserved_size - committed_size
        self.assertEquals(ucr.Size, ucr_size)

    def test_get_UCR_segment_list_all(self):
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        walker = win7heapwalker.Win7HeapFinder()
        for addr, size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            load = heap.loadMembers(self._mappings, 10)            
            self.assertTrue(walker.is_heap(self._mappings, h))
            # get free UCRS from heap
            reserved_ucrs = heap.get_free_UCR_segment_list(self._mappings)
            all_ucrs = []
            # UCR size should add on all UCR for all segments
            for segment in heap.get_segment_list(self._mappings):
                all_ucrs.extend(segment.get_UCR_segment_list(self._mappings))
            total_ucr_size = sum([ucr.Size for ucr in all_ucrs])
            # sum of all existing UCR. not just free UCR
            self.assertEquals(len(all_ucrs), heap.Counters.TotalUCRs)
            # check numbers.
            reserved_size = heap.Counters.TotalMemoryReserved
            committed_size = heap.Counters.TotalMemoryCommitted
            ucr_size = reserved_size - committed_size
            self.assertEquals(total_ucr_size, ucr_size)


    def test_get_segment_list(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        segments = heap.get_segment_list(self._mappings)
        self.assertEquals(heap.Counters.TotalSegments, 1)
        self.assertEquals(len(segments), heap.Counters.TotalSegments)
        segment = segments[0]
        self.assertEquals(segment.SegmentSignature,0xffeeffee)
        self.assertEquals(segment.FirstEntry.value,0x5c0588)
        self.assertEquals(segment.LastValidEntry.value,0x06c0000)
        # only segment is self heap here
        self.assertEquals(segment.Heap.value,addr)
        self.assertEquals(segment.BaseAddress.value,addr)
        # checkings size. a page is 4096 in this example.
        valid_alloc_size = (heap.Segment.LastValidEntry.value
                             - heap.Segment.FirstEntry.value)
        meta_size = (heap.Segment.FirstEntry.value
                        - heap.Segment.BaseAddress.value)
        committed_size = heap.Counters.TotalMemoryCommitted
        reserved_size = heap.Counters.TotalMemoryReserved
        ucr_size = reserved_size - committed_size
        self.assertEquals(segment.NumberOfPages*4096,reserved_size)
        self.assertEquals(segment.NumberOfPages*4096,0x100000) # example
        self.assertEquals(reserved_size, meta_size+valid_alloc_size)

    def test_get_segment_list_all(self):
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        walker = win7heapwalker.Win7HeapFinder()
        for addr, size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            load = heap.loadMembers(self._mappings, 10)            
            self.assertTrue(walker.is_heap(self._mappings, h))

            segments = heap.get_segment_list(self._mappings)
            self.assertEquals(len(segments), heap.Counters.TotalSegments)
            pages = 0 
            total_size = 0
            for segment in segments:
                self.assertEquals(segment.SegmentSignature,0xffeeffee)
                self.assertEquals(segment.Heap.value,addr)
                self.assertLess(segment.BaseAddress.value,
                                segment.FirstEntry.value)
                self.assertLess(segment.FirstEntry.value,
                                segment.LastValidEntry.value)
                valid_alloc_size = (segment.LastValidEntry.value
                                        - segment.FirstEntry.value)
                meta_size = segment.FirstEntry.value - segment.BaseAddress.value
                pages += segment.NumberOfPages
                total_size += valid_alloc_size+meta_size
            # Heap resutls for all segments
            committed_size = heap.Counters.TotalMemoryCommitted
            reserved_size = heap.Counters.TotalMemoryReserved
            self.assertEquals(pages*4096,reserved_size)
            self.assertEquals(total_size,reserved_size)

    def test_get_chunks(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        allocated, free = heap.get_chunks(self._mappings)
        s_allocated = sum([c[1] for c in allocated])
        s_free = sum([c[1] for c in free])
        total = allocated+free
        total.sort()
        s_total = sum([c[1] for c in total])

        # in this example, its a single continuous segment
        for i in range(len(total)-1):
            if total[i][0]+total[i][1] != total[i+1][0]:
                self.fail('Chunk Gap between %s %s '%(total[i], total[i+1]))
        chunks_size = total[-1][0]+total[-1][1]-total[0][0]
        #
        valid_alloc_size = (heap.Segment.LastValidEntry.value
                             - heap.Segment.FirstEntry.value)
        meta_size = (heap.Segment.FirstEntry.value
                        - heap.Segment.BaseAddress.value)
        committed_size = heap.Counters.TotalMemoryCommitted
        reserved_size = heap.Counters.TotalMemoryReserved
        ucr_size = reserved_size - committed_size

        # 1 chunk is 8 bytes.
        self.assertEquals(s_free/8, heap.TotalFreeSize)
        self.assertEquals(committed_size, meta_size+chunks_size)
        self.assertEquals(reserved_size, meta_size+chunks_size+ucr_size)
        
        # LFH bins are in some chunks, at heap.FrontEndHeap

    def test_get_chunks_all(self):
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        walker = win7heapwalker.Win7HeapFinder()
        for addr, size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            load = heap.loadMembers(self._mappings, 10)            
            self.assertTrue(walker.is_heap(self._mappings, h))

            allocated, free = heap.get_chunks(self._mappings)
            s_allocated = sum([c[1] for c in allocated])
            s_free = sum([c[1] for c in free])
            total = allocated+free
            total.sort()
            s_total = sum([c[1] for c in total])
            # HEAP counters
            committed_size = heap.Counters.TotalMemoryCommitted
            reserved_size = heap.Counters.TotalMemoryReserved
            ucr_size = reserved_size - committed_size

            # in some segments, they are non-contiguous segments
            chunks_size = sum([chunk[1] for chunk in total])
            # chunks are in all segments
            alloc_size = 0
            for segment in heap.get_segment_list(self._mappings):
                valid_alloc_size = (segment.LastValidEntry.value
                                    - segment.FirstEntry.value)
                alloc_size += valid_alloc_size
            # 1 chunk is 8 bytes.
            self.assertEquals(s_free/8, heap.TotalFreeSize)
            # sum of allocated size for every segment should amount to the
            # sum of all allocated chunk
            self.assertEquals(alloc_size, chunks_size+ucr_size)


    def test_get_freelists(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        allocated, free = heap.get_chunks(self._mappings)
        freelists = heap.get_freelists(self._mappings)
        free_size = sum([x[1] for x in [(hex(x[0]),x[1]) for x in freelists]])
        free_size2 = sum([x[1] for x in free])
        self.assertEquals(heap.TotalFreeSize*8, free_size)
        self.assertEquals(free_size, free_size2)

    def test_get_freelists_all(self):
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        walker = win7heapwalker.Win7HeapFinder()        
        for addr, size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            load = heap.loadMembers(self._mappings, 10)            
            self.assertTrue(walker.is_heap(self._mappings, h))

            allocated, free = heap.get_chunks(self._mappings)
            freelists = heap.get_freelists(self._mappings)
            free_size = sum([x[1] for x in 
                                         [(hex(x[0]),x[1]) for x in freelists]])
            free_size2 = sum([x[1] for x in free])
            self.assertEquals(heap.TotalFreeSize*8, free_size)
            self.assertEquals(free_size, free_size2)


    def test_get_frontend_chunks(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        fth_committed, fth_free = heap.get_frontend_chunks(self._mappings)
        #SizeInCache : 59224L, 
        
        # not much to check...
        lfh = h.readStruct(heap.FrontEndHeap.value, win7heap.LFH_HEAP )
        self.assertEquals(lfh.Heap.value, addr)
        # FIXME: check more.

    def test_get_vallocs(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.get_mapping_for_address(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)
        valloc_committed= heap.get_virtual_allocated_blocks_list(self._mappings)
        
        size = sum([x.ReserveSize for x in valloc_committed])
        # FIXME Maybe ??
        self.assertEquals(heap.Counters.TotalSizeInVirtualBlocks,size)


    def test_get_vallocs_all(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.structures.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        for addr,size in self._known_heaps:
            h = self._mappings.get_mapping_for_address(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            load = heap.loadMembers(self._mappings, 10)
            valloc_committed = heap.get_virtual_allocated_blocks_list(
                                                                 self._mappings)
            size = sum([x.ReserveSize for x in valloc_committed])
            self.assertEquals(heap.Counters.TotalSizeInVirtualBlocks,size)



if __name__ == '__main__':
    logging.basicConfig( stream=sys.stderr, level=logging.INFO)
    #logging.getLogger('testwin7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('types').setLevel(level=logging.DEBUG)
    #logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    #unittest.TextTestRunner(verbosity=2).run(suite)
