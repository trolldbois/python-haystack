#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack import model
from haystack import types
from haystack import utils
from haystack.reverse.win32 import win7heapwalker 

class TestReferenceBook(unittest.TestCase):
    ''' Test the reference book
    '''

    def setUp(self):
        ctypes = types.reload_ctypes(4,4,8)
        self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
        heap = self.mappings.getHeap()
        # execute a loadMembers
        walker = win7heapwalker.Win7HeapWalker(self.mappings, heap, 0)
        self.heap_obj = walker._heap
    
    def tearDown(self):
        model.reset()
        self.mappings = None
        self.heap_obj = None
        pass
    
    def test_keepRef(self):
        import ctypes
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
        ''' The book should contains only unique values tuples.    '''
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

    def test_ref_unicity_2(self):
        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, int, 0xcafecafe)
        model.keepRef(3, int, 0xcafecafe)
        me = model.getRefByAddr( 0xcafecafe )
        self.assertEquals( len(me), 1)

        model.keepRef('4', str, 0xcafecafe)
        me = model.getRefByAddr( 0xcafecafe )
        self.assertEquals( len(me), 2)
        return


    def test_hasRef(self):

        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, float, 0xcafecafe)
        model.keepRef(3, str, 0xcafecafe)

        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertTrue( model.hasRef(str,0xcafecafe))
        self.assertFalse( model.hasRef(unicode,0xcafecafe))
        self.assertFalse( model.hasRef(int,0xdeadbeef))
        
    def test_getRef(self):
        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, float, 0xcafecafe)

        self.assertEquals( model.getRef(int,0xcafecafe), 1)
        self.assertEquals( model.getRef(float,0xcafecafe), 2)
        self.assertIsNone( model.getRef(str,0xcafecafe))
        self.assertIsNone( model.getRef(str,0xdeadbeef))
        self.assertIsNone( model.getRef(int,0xdeadbeef))

        
    def test_delRef(self):
        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, float, 0xcafecafe)
        model.keepRef(3, str, 0xcafecafe)

        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertTrue( model.hasRef(str,0xcafecafe))

        model.delRef(str, 0xcafecafe)
        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertFalse( model.hasRef(str,0xcafecafe))

        model.delRef(str, 0xcafecafe)
        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertFalse( model.hasRef(str,0xcafecafe))

        model.delRef(int, 0xcafecafe)
        self.assertFalse( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertFalse( model.hasRef(str,0xcafecafe))

        model.delRef(float, 0xcafecafe)
        self.assertFalse( model.hasRef(int,0xcafecafe))
        self.assertFalse( model.hasRef(float,0xcafecafe))
        self.assertFalse( model.hasRef(str,0xcafecafe))


        
    '''
        def hasRef(typ,origAddr):

        def getRef(typ,origAddr):

        def getRefByAddr(addr):

        def keepRef(obj,typ=None,origAddr=None):
    '''

class TestCopyModule(unittest.TestCase):
    
    def test_bad(self):
        try:
            from test.structures import bad
            self.assertEquals(bad.BLOCK_SIZE, 16)
        except ImportError as e:
            self.fail(e)



if __name__ == '__main__':
    #logging.basicConfig( stream=sys.stderr, level=logging.INFO )
    #logging.getLogger("listmodel").setLevel(level=logging.DEBUG)    
    #logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)    
    #logging.getLogger("root").setLevel(level=logging.DEBUG)    
    #logging.getLogger("win7heap").setLevel(level=logging.DEBUG)    
    #logging.getLogger("dump_loader").setLevel(level=logging.INFO)    
    #logging.getLogger("memory_mapping").setLevel(level=logging.INFO)    
    logging.basicConfig(level=logging.DEBUG)    
    unittest.main(verbosity=2)

