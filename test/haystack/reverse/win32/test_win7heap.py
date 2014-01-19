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
        from haystack import model
        model.reset()
        self._mappings = None        
        return

    def test_ctypes_sizes(self):
        """ road to faking POINTER :
            get_subtype(attrtype)    # checks for attrtype._type_
            getaddress(attr)        # check for address of attr.contents being a ctypes.xx.from_address(ptr_value)
            
        """
        ctypes = self._mappings.config.ctypes
        from haystack.reverse.win32 import win7heap
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


    def test_heap_read(self):
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
        
        print addr
        print hex( ctypes.addressof( heap ) )
        print heap.Signature, hex(heap.Signature)
        print '*'*80
        
        import code 
        addr = h.start
        heap = h.readStruct( addr, win7heap.HEAP )
        load = heap.loadMembers(self._mappings, -1)
        
        code.interact(local=locals())
        
        self.assertTrue( win7heapwalker.is_heap(self._mappings, h) ) #, '\n'.join([str(m) for m in self._mappings]))
        #import code 
        #code.interact(local=locals())
        

    
    def test_keepRef(self):
        heap = self.mappings.getHeap()
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
    logging.basicConfig( stream=sys.stderr, level=logging.DEBUG )
    #logging.getLogger('testwin7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    #unittest.TextTestRunner(verbosity=2).run(suite)
