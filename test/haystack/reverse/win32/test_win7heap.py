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
        self._mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
        self._known_heaps = [ (0x00390000, 8956), (0x00540000, 868),
                                        ( 0x00580000, 111933), (0x005c0000, 1704080) , 
                                        ( 0x01ef0000, 604), (0x02010000, 61348), 
                                        ( 0x02080000, 474949), (0x021f0000 , 18762),
                                        ( 0x03360000, 604), (0x04030000 , 632),
                                        ( 0x04110000, 1334), (0x041c0000 , 644),
                                        # from free stuf - erroneous 
                                        #( 0x0061a000, 1200),
                                        ]
        return
        
    def tearDown(self):
        model.reset()
        self._mappings = None        
        return

    def test_ctypes_sizes(self):
        """ road to faking POINTER :
            get_subtype(attrtype)    # checks for attrtype._type_
            getaddress(attr)        # check for address of attr.contents being a ctypes.xx.from_address(ptr_value)
            
        """
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap

        ctypes = self._mappings.config.ctypes
        
        self.assertEquals( ctypes.sizeof( win7heap._HEAP_SEGMENT), 64 )
        self.assertEquals( ctypes.sizeof( win7heap._HEAP_ENTRY), 8 )
        self.assertEquals( ctypes.sizeof( ctypes.POINTER(None)), 4 )
        self.assertEquals( ctypes.sizeof( ctypes.POINTER(win7heap._HEAP_TAG_ENTRY)), 4 )
        self.assertEquals( ctypes.sizeof( win7heap._LIST_ENTRY), 8 )
        self.assertEquals( ctypes.sizeof( ctypes.POINTER(win7heap._HEAP_LIST_LOOKUP)), 4 )
        self.assertEquals( ctypes.sizeof( ctypes.POINTER(win7heap._HEAP_PSEUDO_TAG_ENTRY)), 4 )
        self.assertEquals( ctypes.sizeof( ctypes.POINTER(win7heap._HEAP_LOCK)), 4 )
        self.assertEquals( ctypes.sizeof( ctypes.c_ubyte), 1 )
        self.assertEquals( ctypes.sizeof( (ctypes.c_ubyte*1)), 1 )
        self.assertEquals( ctypes.sizeof( win7heap._HEAP_COUNTERS), 84 )
        self.assertEquals( ctypes.sizeof( win7heap._HEAP_TUNING_PARAMETERS), 8 )

        self.assertEquals( ctypes.sizeof( win7heap.HEAP ) , 312 )
        self.assertEquals( utils.offsetof( win7heap.HEAP , 'Signature') , 100 )


    def test_is_heap(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        h = self._mappings.getMmapForAddr(0x005c0000)
        self.assertEquals(h.getByteBuffer()[0:10],'\xc7\xf52\xbc\xc9\xaa\x00\x01\xee\xff')
        addr = h.start
        self.assertEquals( addr , 6029312)
        heap = h.readStruct( addr, win7heap.HEAP )
        
        # check that haystack memory_mapping works
        self.assertEquals( ctypes.addressof( h._local_mmap_content ), ctypes.addressof( heap ) )
        # check heap.Signature
        self.assertEquals( heap.Signature , 4009750271L ) # 0xeeffeeff
        load = heap.loadMembers(self._mappings, 10)
        self.assertTrue(win7heapwalker.is_heap(self._mappings, h))

        
    def test_is_heap_all(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        for addr, size in self._known_heaps:
            h = self._mappings.getMmapForAddr(addr)
            heap = h.readStruct( addr, win7heap.HEAP )
            # check heap.Signature
            self.assertEquals( heap.Signature , 4009750271L ) # 0xeeffeeff
            load = heap.loadMembers(self._mappings, 10)
            
            self.assertTrue(win7heapwalker.is_heap(self._mappings, h))
        

    def test_get_UCR_segment_list(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        ucrs = heap.get_UCR_segment_list(self._mappings)
        self.assertEquals(heap.UCRIndex.value, 0x5c0590)
        self.assertEquals(heap.Counters.TotalUCRs, 1)
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


    def test_get_segment_list(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
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
        valid_alloc_size = heap.Segment.LastValidEntry.value - heap.Segment.FirstEntry.value
        meta_size = heap.Segment.FirstEntry.value - heap.Segment.BaseAddress.value
        committed_size = heap.Counters.TotalMemoryCommitted
        reserved_size = heap.Counters.TotalMemoryReserved
        ucr_size = reserved_size - committed_size
        self.assertEquals(segment.NumberOfPages*4096,reserved_size)
        self.assertEquals(segment.NumberOfPages*4096,0x100000) # example
        self.assertEquals(reserved_size, meta_size+valid_alloc_size)



    def test_get_chunks(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
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
        valid_alloc_size = heap.Segment.LastValidEntry.value - heap.Segment.FirstEntry.value
        meta_size = heap.Segment.FirstEntry.value - heap.Segment.BaseAddress.value
        committed_size = heap.Counters.TotalMemoryCommitted
        reserved_size = heap.Counters.TotalMemoryReserved
        ucr_size = reserved_size - committed_size

        # 1 chunk is 8 bytes.
        self.assertEquals(s_free/8, heap.TotalFreeSize)
        self.assertEquals(committed_size, meta_size+chunks_size)
        self.assertEquals(reserved_size, meta_size+chunks_size+ucr_size)
        
        # LFH bins are in some chunks, at heap.FrontEndHeap
        

    def test_get_freelists(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)

        allocated, free = heap.get_chunks(self._mappings)
        logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
        freelists = heap.get_freelists(self._mappings)
        freelists2 = heap.get_freelists2(self._mappings)
        print len(freelists)
        print len(freelists2)
        print freelists == freelists2

        import code
        code.interact(local=locals())


    def test_getFrontendChunks(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)
        logging.getLogger('testwin7heap').setLevel(level=logging.DEBUG)
        logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
        logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
        logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
        fth_committed, fth_free = heap.getFrontendChunks(self._mappings)

    def test_getVallocBlocks(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        ctypes = self._mappings.config.ctypes
        addr = 0x005c0000
        h = self._mappings.getMmapForAddr(addr)
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, 10)
        logging.getLogger('testwin7heap').setLevel(level=logging.DEBUG)
        logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
        logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
        logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
        valloc_committed = [ block for block in heap.iterateListField(self._mappings, 'VirtualAllocdBlocks') ]
        #valloc_free = [] # FIXME TODO


    def test_all(self):
        s_allocated = sum([c[1] for c in allocated])
        s_free = sum([c[1] for c in free])
        s_freelists = sum([c[1] for c in freelists])
        s_committed = sum([c[1] for c in fth_committed])
        s_free_fth = sum([c[1] for c in fth_free])
        
        s_a = s_allocated+s_committed
        s_f = s_free+s_free_fth
        print 'allocated:',s_a
        print 'free:', s_f
        print 'total:',s_a+s_f
        print 'map size:', 1704080


        vallocs, va_free = self._get_virtualallocations()
        chunks, free_chunks = self._get_chunks()
        fth_chunks, fth_free = self._get_frontend_chunks()

        lst = vallocs+chunks+fth_chunks+va_free+free_Chunks+fth_free
        s_lst = sum([c[1] for c in lst])
        print s_lst
        import code
        code.interact(local=locals())
    
    
    
    def test_keepRef(self):
        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        heap = self._mappings.getHeap()
        # execute a loadMembers
        walker = win7heapwalker.Win7HeapWalker(self.mappings, heap, 0)
        self.heap_obj = walker._heap
        self.assertNotEqual( self.mappings, None )
            
        for fname, ftype in self.heap_obj.getFields():
            attr = getattr(self.heap_obj, fname)
            if ctypes.is_cstring_pointer(ftype):
                # ignore that - attr_addr = getaddress(attr.ptr)
                continue
            elif ctypes.is_pointer_type(ftype):
                attr_addr = getaddress(attr)
            else:
                continue
            if attr_addr == 0:
                continue
            self.assertTrue( utils.is_valid_address_value(attr_addr, self.mappings), '%s: 0x%x is not valid'%(fname, attr_addr))
            # the book should register struct type, not pointer to strut type
            attr_type = model.get_subtype(ftype)
            # look in the books
            saved = model.getRefByAddr( attr_addr )
            _class, _addr, _obj = saved[0]

            self.assertEquals( attr_addr, _addr)
            self.assertEquals( attr_type, _class, '%s != %s' %(type(ftype), type(_class)))
            self.assertTrue( model.hasRef( model.get_subtype(ftype), attr_addr))
        
        return            

    @unittest.expectedFailure #('HEAP, HEAP_SEGMENT and HEAP_ENTRY')
    def test_ref_unicity(self):
        """ The book should contains only unique values tuples.    """

        # You have to import after ctypes has been tuned ( mapping loader )
        from haystack.reverse.win32 import win7heapwalker, win7heap
        heap = self.mappings.getHeap()
        # execute a loadMembers
        walker = win7heapwalker.Win7HeapWalker(self.mappings, heap, 0)
        self.heap_obj = walker._heap

        self.assertNotEqual( self.mappings, None )
        
        fails = dict()
        for (typ,addr),obj in model.getRefs():
            me = model.getRefByAddr( addr )
            if len(me) > 1:
                if addr not in fails:
                    fails[addr] = list()
                else:
                    continue
                for _typ, _addr, _obj in me:
                    fails[addr].append( _typ )
        
        for addr, types in fails.items():
            log.debug('\n\n**** %0.8x '%(addr))
            log.debug('\n'.join([str(t) for t in types]))
        
        addresses = [ addr for (typ,addr),obj in model.getRefs()]
        s_addrs = set(addresses)
        self.assertEquals( len(addresses), len(s_addrs))


if __name__ == '__main__':
    logging.basicConfig( stream=sys.stderr, level=logging.INFO)
    #logging.getLogger('testwin7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('types').setLevel(level=logging.DEBUG)
    logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    #unittest.TextTestRunner(verbosity=2).run(suite)
