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
    """Test the reference book."""
    
    def setUp(self):
        model.reset()
    
    def test_keepRef(self):
        # same address, same type
        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, int, 0xcafecafe)
        model.keepRef(3, int, 0xcafecafe)
        me = model.getRefByAddr( 0xcafecafe )
        # only one ref ( the first)
        self.assertEquals( len(me), 1)

        # different type, same address
        model.keepRef('4', str, 0xcafecafe)
        me = model.getRefByAddr( 0xcafecafe )
        # multiple refs
        self.assertEquals( len(me), 2)
        return


    def test_hasRef(self):
        # same address, different types
        model.keepRef(1, int, 0xcafecafe)
        model.keepRef(2, float, 0xcafecafe)
        model.keepRef(3, str, 0xcafecafe)

        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertTrue( model.hasRef(str,0xcafecafe))
        self.assertFalse( model.hasRef(unicode,0xcafecafe))
        self.assertFalse( model.hasRef(int,0xdeadbeef))
        me = model.getRefByAddr( 0xcafecafe )
        # multiple refs
        self.assertEquals( len(me), 3)
        
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
        # del one type
        model.delRef(str, 0xcafecafe)
        self.assertTrue( model.hasRef(int,0xcafecafe))
        self.assertTrue( model.hasRef(float,0xcafecafe))
        self.assertFalse( model.hasRef(str,0xcafecafe))
        # try harder, same type, same result
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

    def test_get_subtype(self):
        types.reset_ctypes()
        import ctypes
        class X(ctypes.Structure):
            _fields_ = [('p',ctypes.POINTER(ctypes.c_long))]
        PX = ctypes.POINTER(X)
        self.assertEquals(model.get_subtype(PX), X)
        
        ctypes = types.reload_ctypes(4,4,8) # different arch
        class Y(ctypes.Structure):
            _fields_ = [('p',ctypes.POINTER(ctypes.c_long))]
        PY = ctypes.POINTER(Y)
        self.assertEquals(model.get_subtype(PY), Y)

class TestCopyModule(unittest.TestCase):
    
    def test_registerModule(self):
        from haystack import model
        model.reset()

        try:
            from test.structures import good
            from test.structures import good_gen
            from test.structures import bad_gen
            # copy bad_gen in good
            model.copyGeneratedClasses(bad_gen,good)
            model.copyGeneratedClasses(good_gen,good)
            self.assertIn('Struct1', good.__dict__)
            self.assertIn('Struct2', good.__dict__)
            self.assertNotIn('Struct1_py', good.__dict__)
            self.assertNotIn('expectedValues', good.Struct1.__dict__)
        except ImportError as e:
            self.fail(e)
        try:
            from test.structures import bad
            # test if module has members
            self.assertEquals(bad.BLOCK_SIZE, 16)
            self.assertIn('Struct1', bad.__dict__)
            self.assertIn('expectedValues', bad.Struct1.__dict__)
            # same Struct1 object is imported in bad and good 
            self.assertIn('expectedValues', good.Struct1.__dict__)
            self.assertNotIn('expectedValues', good.Struct2.__dict__)
        except ImportError as e:
            self.fail(e)

        # test if register works (creates POPO)
        model.registerModule(bad)
        self.assertIn('Struct1_py', bad.__dict__)
        self.assertIn('expectedValues', bad.Struct1.__dict__)
        # POPO is not create in good
        self.assertNotIn('Struct1_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        model.registerModule(good) # creates POPO for the rest
        self.assertIn('Struct2_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        # expectedValues is in a function
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        # add an expectedValues
        good.populate()
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertIn('expectedValues', good.Struct2.__dict__)
        

if __name__ == '__main__':
    #logging.basicConfig( stream=sys.stderr, level=logging.INFO )
    #logging.getLogger("listmodel").setLevel(level=logging.DEBUG)    
    #logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)    
    #logging.getLogger("root").setLevel(level=logging.DEBUG)    
    #logging.getLogger("win7heap").setLevel(level=logging.DEBUG)    
    #logging.getLogger("dump_loader").setLevel(level=logging.INFO)    
    #logging.getLogger("memory_mapping").setLevel(level=logging.INFO)    
    #logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)

