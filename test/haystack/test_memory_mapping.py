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

from haystack import dump_loader
from haystack import memory_mapping
from haystack import utils
from haystack import types
from haystack.reverse import context

log = logging.getLogger('test_memory_mapping')

class TestMmapHack(unittest.TestCase):
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
        maps = memory_mapping.readLocalProcessMappings()
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
        maps = memory_mapping.readLocalProcessMappings()
        ret=[m for m in maps if heapmap in m]
        # heapmap is a pointer value in local memory
        self.assertEquals( len(ret), 1)
        # heapmap is a pointer value to this executable?
        self.assertEquals( ret[0].pathname, fname)

        import ctypes
        self.assertIn('CTypesProxy-4:4:8', str(ctypes))


class TestMappingsLinux(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.ssh = context.get_context('test/dumps/ssh/ssh.1')
        pass

    def setUp(self):    
        pass

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
        self.assertEquals(mappings.get_context(0xb84e02d3).heap, mappings.getMmapForAddr(0xb84e02d3))
    
    def test_get_user_allocations(self):
        mappings = self.ssh.mappings
        allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
        self.assertEquals( len(allocs), 2568)

    def test_getMmap(self):
        mappings = self.ssh.mappings
        self.assertEquals( len(mappings.getMmap('[heap]')), 1)
        self.assertEquals( len(mappings.getMmap('None')), 9)

    def test_getMmapForAddr(self):
        mappings = self.ssh.mappings
        self.assertEquals(mappings.getHeap(), mappings.getMmapForAddr(0xb84e02d3))

    def test_getHeap(self):
        mappings = self.ssh.mappings
        self.assertTrue( isinstance(mappings.getHeap(), memory_mapping.MemoryMapping))
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
        self.assertTrue( isinstance(mappings[0], memory_mapping.MemoryMapping))
        self.assertTrue( isinstance(mappings[len(mappings)-1], memory_mapping.MemoryMapping))
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
        
    @unittest.skip('')
    def test_search_win_heaps(self):
        pass
    
    @unittest.skip('')
    def test_get_target_system(self):
        pass
    
    @unittest.skip('')
    def test_get_mmap_for_haystack_addr(self):
        pass    
        

class TestMappingsWin32(unittest.TestCase):

    def setUp(self):    
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
        self.assertEquals(mappings.get_context(0x0062d000).heap, mappings.getMmapForAddr(0x005c0000))
        self.assertEquals(mappings.get_context(0x0063e123).heap, mappings.getMmapForAddr(0x005c0000))
        self.putty.reset()
        self.putty = None

    
    def test_get_user_allocations(self):
        """ FIXME: this methods expands a full reversal of all HEAPs.
        It should probably be in haystack.reverse."""
        mappings = self.mappings
        allocs = list(mappings.get_user_allocations(mappings, mappings.getHeap()))
        self.assertEquals( len(allocs), 2273)

    def test_getMmap(self):
        mappings = self.putty.mappings
        with self.assertRaises(IndexError):
            self.assertEquals( len(mappings.getMmap('[heap]')), 1)
        self.assertEquals( len(mappings.getMmap('None')), 71)

    @unittest.skip('')
    def test_getMmapForAddr(self):
        pass

    def test_getHeap(self):
        mappings = self.mappings
        self.assertTrue( isinstance(mappings.getHeap(), memory_mapping.MemoryMapping))
        self.assertEquals( mappings.getHeap().start, 0x005c0000)
        self.assertEquals( mappings.getHeap().pathname, 'None')

    def test_getHeaps(self):
        mappings = self.putty.mappings
        self.assertEquals( len(mappings.getHeaps()), 12)

    @unittest.expectedFailure # FIXME
    def test_getStack(self):
        #TODO win32        
        mappings = self.putty.mappings
        #print ''.join(['%s\n'%(m) for m in mappings])        
        #print mappings.getStack() # no [stack]
        self.assertEquals( mappings.getStack().start, 0x00400000)
        self.assertEquals( mappings.getStack().pathname, '''C:\Program Files (x86)\PuTTY\putty.exe''')
        
    def test_contains(self):
        mappings = self.putty.mappings
        for m in mappings:
            self.assertTrue( m.start in mappings)
            self.assertTrue( (m.end-1) in mappings)

    def test_len(self):
        mappings = self.putty.mappings
        self.assertEquals( len(mappings), 403)
        
    def test_getitem(self):
        mappings = self.putty.mappings
        self.assertTrue( isinstance(mappings[0], memory_mapping.MemoryMapping))
        self.assertTrue( isinstance(mappings[len(mappings)-1], memory_mapping.MemoryMapping))
        with self.assertRaises(IndexError):
            mappings[0x0005c000]
        
    def test_iter(self):
        mappings = self.putty.mappings
        mps = [m for m in mappings]
        mps2 = [m for m in mappings.mappings]
        self.assertEquals(mps, mps2)

    def test_setitem(self):
        mappings = self.putty.mappings
        with self.assertRaises(NotImplementedError):
            mappings[0x0005c000]=1

    @unittest.skip('')
    def test_search_win_heaps(self):
        pass

    @unittest.skip('')
    def test_search_nux_heaps(self):
        pass
    
    @unittest.skip('')
    def test_get_target_system(self):
        pass
    
    @unittest.skip('')
    def test_get_mmap_for_haystack_addr(self):
        pass    

class TestReferenceBook(unittest.TestCase):
    """Test the reference book."""
    
    def setUp(self):
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
    logging.basicConfig(level=logging.INFO)
    #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    logging.getLogger('basicmodel').setLevel(logging.INFO)
    logging.getLogger('model').setLevel(logging.INFO)
    logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)


