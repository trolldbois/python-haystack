#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import os
import unittest
import logging
import tempfile
import time
import mmap
import struct

from haystack import model
from haystack import dump_loader
from haystack import utils
from haystack import types
from haystack.reverse import context
from haystack.mappings.base import MemoryMapping
from haystack.mappings.process import readLocalProcessMappings

log = logging.getLogger('test_memory_mapping')

from test.haystack import SrcTests

class TestMmapHack(unittest.TestCase):
    def setUp(self):    
        model.reset()

    def test_mmap_hack64(self):
        ctypes = types.reload_ctypes(8,8,16)
        real_ctypes_long = ctypes.get_real_ctypes_member('c_ulong')
        fname = os.path.normpath(os.path.abspath(__file__))
        fin = file(fname)
        local_mmap_bytebuffer = mmap.mmap(fin.fileno(), 1024, access=mmap.ACCESS_READ)
        fin.close()
        fin = None
        # yeap, that right, I'm stealing the pointer value. DEAL WITH IT.
        heapmap = struct.unpack('L', (real_ctypes_long).from_address(id(local_mmap_bytebuffer) + 
                                        2*(ctypes.sizeof(real_ctypes_long))))[0]
        log.debug('MMAP HACK: heapmap: 0x%0.8x'%(heapmap) )
        maps = readLocalProcessMappings()
        ret=[m for m in maps if heapmap in m]
        # heapmap is a pointer value in local memory
        self.assertEquals( len(ret), 1)
        # heapmap is a pointer value to this executable?
        self.assertEquals( ret[0].pathname, fname)

        import ctypes
        self.assertIn('CTypesProxy-8:8:16', str(ctypes))


    def test_mmap_hack32(self):
        ctypes = types.reload_ctypes(4,4,8)
        real_ctypes_long = ctypes.get_real_ctypes_member('c_ulong')
        fname = os.path.normpath(os.path.abspath(__file__))
        fin = file(fname)
        local_mmap_bytebuffer = mmap.mmap(fin.fileno(), 1024, access=mmap.ACCESS_READ)
        fin.close()
        fin = None
        # yeap, that right, I'm stealing the pointer value. DEAL WITH IT.
        heapmap = struct.unpack('L', (real_ctypes_long).from_address(id(local_mmap_bytebuffer) + 
                                        2*(ctypes.sizeof(real_ctypes_long))))[0]
        log.debug('MMAP HACK: heapmap: 0x%0.8x'%(heapmap) )
        maps = readLocalProcessMappings()
        ret=[m for m in maps if heapmap in m]
        # heapmap is a pointer value in local memory
        self.assertEquals( len(ret), 1)
        # heapmap is a pointer value to this executable?
        self.assertEquals( ret[0].pathname, fname)

        import ctypes
        self.assertIn('CTypesProxy-4:4:8', str(ctypes))


class TestMappingsLinux(SrcTests):

    @classmethod
    def setUpClass(self):
        self.ssh = context.get_context('test/dumps/ssh/ssh.1')
        pass

    def setUp(self):    
        model.reset()

    def tearDown(self):
        self.ssh.reset()
        import haystack
        from haystack import model
        haystack.model.reset()
        pass

    def test_get_context(self):
        mappings = self.ssh.mappings
        #print ''.join(['%s\n'%(m) for m in mappings])        
        with self.assertRaises(ValueError):
            mappings.get_context(0x0)
        with self.assertRaises(ValueError):
            mappings.get_context(0xb76e12d3)
        #[heap]
        self.assertEquals(mappings.get_context(0xb84e02d3).heap, mappings.get_mapping_for_address(0xb84e02d3))
    
    def test_get_user_allocations(self):
        mappings = self.ssh.mappings
        allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
        self.assertEquals( len(allocs), 2568)

    def test_get_mapping(self):
        mappings = self.ssh.mappings
        self.assertEquals( len(mappings.get_mapping('[heap]')), 1)
        self.assertEquals( len(mappings.get_mapping('None')), 9)

    def test_get_mapping_for_address(self):
        mappings = self.ssh.mappings
        self.assertEquals(mappings.getHeap(), mappings.get_mapping_for_address(0xb84e02d3))

    def test_getHeap(self):
        mappings = self.ssh.mappings
        self.assertTrue( isinstance(mappings.getHeap(), MemoryMapping))
        self.assertEquals( mappings.getHeap().start, 0xb84e0000)
        self.assertEquals( mappings.getHeap().pathname, '[heap]')

    def test_getHeaps(self):
        mappings = self.ssh.mappings
        self.assertEquals( len(mappings.getHeaps()), 1) # really ?

    def test_getStack(self):
        mappings = self.ssh.mappings
        self.assertEquals( mappings.getStack().start, 0xbff45000)
        self.assertEquals( mappings.getStack().pathname, '[stack]')
        
    def test_contains(self):
        mappings = self.ssh.mappings
        for m in mappings:
            self.assertTrue( m.start in mappings)
            self.assertTrue( (m.end-1) in mappings)

    def test_len(self):
        mappings = self.ssh.mappings
        self.assertEquals( len(mappings), 70)
        
    def test_getitem(self):
        mappings = self.ssh.mappings
        self.assertTrue( isinstance(mappings[0], MemoryMapping))
        self.assertTrue( isinstance(mappings[len(mappings)-1], MemoryMapping))
        with self.assertRaises(IndexError):
            mappings[0x0005c000]
        
    def test_iter(self):
        mappings = self.ssh.mappings
        mps = [m for m in mappings]
        mps2 = [m for m in mappings.mappings]
        self.assertEquals(mps, mps2)

    def test_setitem(self):
        mappings = self.ssh.mappings
        with self.assertRaises(NotImplementedError):
            mappings[0x0005c000] = 1
        
    def test_get_target_system(self):
        mappings = self.ssh.mappings
        x = mappings.get_target_system()
        self.assertEquals(x,'linux')
        pass
    

    def test_is_valid_address(self):
        mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        from test.src import ctypes5_gen32
        # struct a - basic types
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
        offset = self.offsets['struct_d'][0]
        m = mappings.get_mapping_for_address(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(mappings, 10 )

        self.assertTrue(mappings.is_valid_address(d.a))
        self.assertTrue(mappings.is_valid_address(d.b))
        self.assertTrue(mappings.is_valid_address(d.d))
        self.assertTrue(mappings.is_valid_address(d.h))
        pass

    def test_is_valid_address_value(self):
        mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        from test.src import ctypes5_gen32
        # struct a - basic types
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
        offset = self.offsets['struct_d'][0]
        m = mappings.get_mapping_for_address(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(mappings, 10 )

        self.assertTrue(mappings.is_valid_address(d.a.value))
        self.assertTrue(mappings.is_valid_address(d.b.value))
        self.assertTrue(mappings.is_valid_address(d.d.value))
        self.assertTrue(mappings.is_valid_address(d.h.value))
        pass


class TestMappingsWin32(unittest.TestCase):

    def setUp(self):    
        model.reset()
        self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
        pass

    def tearDown(self):
        pass

    @unittest.skip('require reverser')
    def test_get_context(self):
        self.putty = context.get_context('test/dumps/putty/putty.1.dump')
        mappings = self.putty.mappings
        #print ''.join(['%s\n'%(m) for m in mappings])        
        with self.assertRaises(ValueError):
            mappings.get_context(0x0)
        with self.assertRaises(ValueError):
            mappings.get_context(0xb76e12d3)
        #[heap] children
        self.assertEquals(mappings.get_context(0x0062d000).heap, mappings.get_mapping_for_address(0x005c0000))
        self.assertEquals(mappings.get_context(0x0063e123).heap, mappings.get_mapping_for_address(0x005c0000))
        self.putty.reset()
        self.putty = None

    
    def test_get_user_allocations(self):
        """ FIXME: this methods expands a full reversal of all HEAPs.
        It should probably be in haystack.reverse."""
        mappings = self.mappings
        allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
        self.assertEquals( len(allocs), 2273)

    def test_get_mapping(self):
        mappings = self.mappings
        with self.assertRaises(IndexError):
            self.assertEquals( len(mappings.get_mapping('[heap]')), 1)
        self.assertEquals( len(mappings.get_mapping('None')), 71)

    def test_get_mapping_for_address(self):
        m = self.mappings.get_mapping_for_address(0x005c0000)
        self.assertNotEquals(m, False)
        self.assertEquals(m.start, 0x005c0000)
        self.assertEquals(m.end, 0x00619000)

    def test_getHeap(self):
        mappings = self.mappings
        self.assertTrue( isinstance(mappings.getHeap(), MemoryMapping))
        self.assertEquals( mappings.getHeap().start, 0x005c0000)
        self.assertEquals( mappings.getHeap().pathname, 'None')
        m = mappings.getHeap()
        buf = m.readBytes(m.start,500)
        from haystack.structures.win32 import win7heap
        x = win7heap.HEAP.from_buffer_copy(buf)
        print win7heap.HEAP.Signature
        print repr(buf[100:104])
        print hex(x.Signature)
        print mappings.config.ctypes.sizeof(x)

    def test_getHeaps(self):
        mappings = self.mappings
        self.assertEquals( len(mappings.getHeaps()), 12)

    @unittest.expectedFailure # FIXME
    def test_getStack(self):
        #TODO win32        
        mappings = self.mappings
        #print ''.join(['%s\n'%(m) for m in mappings])        
        #print mappings.getStack() # no [stack]
        self.assertEquals( mappings.getStack().start, 0x00400000)
        self.assertEquals( mappings.getStack().pathname, '''C:\Program Files (x86)\PuTTY\putty.exe''')
        
    def test_contains(self):
        mappings = self.mappings
        for m in mappings:
            self.assertTrue( m.start in mappings)
            self.assertTrue( (m.end-1) in mappings)

    def test_len(self):
        mappings = self.mappings
        self.assertEquals( len(mappings), 403)
        
    def test_getitem(self):
        mappings = self.mappings
        self.assertTrue( isinstance(mappings[0], MemoryMapping))
        self.assertTrue( isinstance(mappings[len(mappings)-1], MemoryMapping))
        with self.assertRaises(IndexError):
            mappings[0x0005c000]
        
    def test_iter(self):
        mappings = self.mappings
        mps = [m for m in mappings]
        mps2 = [m for m in mappings.mappings]
        self.assertEquals(mps, mps2)

    def test_setitem(self):
        mappings = self.mappings
        with self.assertRaises(NotImplementedError):
            mappings[0x0005c000]=1

    def test_search_win_heaps(self):
        mappings = self.mappings
        heaps = mappings.search_win_heaps()
        self.assertEquals(len(heaps), 12)
        self.assertEquals(len(mappings.getHeaps()), 12)

    def test_get_target_system(self):
        x = self.mappings.get_target_system()
        self.assertEquals(x,'win32')
        pass
    


class TestReferenceBook(unittest.TestCase):
    """Test the reference book."""
    
    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/src/test-ctypes6.32.dump')

    def tearDown(self):
        #self.mappings.reset()
        pass
    
    def test_keepRef(self):
        self.assertEquals(len(self.mappings.getRefByAddr(0xcafecafe)), 0)
        self.assertEquals(len(self.mappings.getRefByAddr(0xdeadbeef)), 0)

        # same address, same type
        self.mappings.keepRef(1, int, 0xcafecafe)
        self.mappings.keepRef(2, int, 0xcafecafe)
        self.mappings.keepRef(3, int, 0xcafecafe)
        me = self.mappings.getRefByAddr( 0xcafecafe )
        # only one ref ( the first)
        self.assertEquals( len(me), 1)

        # different type, same address
        self.mappings.keepRef('4', str, 0xcafecafe)
        me = self.mappings.getRefByAddr( 0xcafecafe )
        # multiple refs
        self.assertEquals( len(me), 2)
        return

    def test_hasRef(self):
        self.assertEquals(len(self.mappings.getRefByAddr(0xcafecafe)), 0)
        self.assertEquals(len(self.mappings.getRefByAddr(0xdeadbeef)), 0)

        # same address, different types
        self.mappings.keepRef(1, int, 0xcafecafe)
        self.mappings.keepRef(2, float, 0xcafecafe)
        self.mappings.keepRef(3, str, 0xcafecafe)

        self.assertTrue( self.mappings.hasRef(int,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(float,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(str,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(unicode,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(int,0xdeadbeef))
        me = self.mappings.getRefByAddr( 0xcafecafe )
        # multiple refs
        self.assertEquals( len(me), 3)
        
    def test_getRef(self):
        self.assertEquals(len(self.mappings.getRefByAddr(0xcafecafe)), 0)
        self.assertEquals(len(self.mappings.getRefByAddr(0xdeadbeef)), 0)
        self.mappings.keepRef(1, int, 0xcafecafe)
        self.mappings.keepRef(2, float, 0xcafecafe)

        self.assertEquals( self.mappings.getRef(int,0xcafecafe), 1)
        self.assertEquals( self.mappings.getRef(float,0xcafecafe), 2)
        self.assertIsNone( self.mappings.getRef(str,0xcafecafe))
        self.assertIsNone( self.mappings.getRef(str,0xdeadbeef))
        self.assertIsNone( self.mappings.getRef(int,0xdeadbeef))


    def test_delRef(self):
        self.assertEquals(len(self.mappings.getRefByAddr(0xcafecafe)), 0)
        self.assertEquals(len(self.mappings.getRefByAddr(0xdeadbeef)), 0)

        self.mappings.keepRef(1, int, 0xcafecafe)
        self.mappings.keepRef(2, float, 0xcafecafe)
        self.mappings.keepRef(3, str, 0xcafecafe)

        self.assertTrue( self.mappings.hasRef(int,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(float,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(str,0xcafecafe))
        # del one type
        self.mappings.delRef(str, 0xcafecafe)
        self.assertTrue( self.mappings.hasRef(int,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(float,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(str,0xcafecafe))
        # try harder, same type, same result
        self.mappings.delRef(str, 0xcafecafe)
        self.assertTrue( self.mappings.hasRef(int,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(float,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(str,0xcafecafe))

        self.mappings.delRef(int, 0xcafecafe)
        self.assertFalse( self.mappings.hasRef(int,0xcafecafe))
        self.assertTrue( self.mappings.hasRef(float,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(str,0xcafecafe))

        self.mappings.delRef(float, 0xcafecafe)
        self.assertFalse( self.mappings.hasRef(int,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(float,0xcafecafe))
        self.assertFalse( self.mappings.hasRef(str,0xcafecafe))

 

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    #logging.basicConfig(level=logging.INFO)
    #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    #logging.getLogger('basicmodel').setLevel(logging.INFO)
    #logging.getLogger('model').setLevel(logging.INFO)
    #logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)


