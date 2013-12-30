#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

# init ctypes with a controlled type size
from haystack import model
from haystack import utils

import operator
import os
import struct
import unittest


import ctypes

def make_types():
    # make some structures.
    class St(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_int) ]
    class St2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_long) ]
    class SubSt2(ctypes.Structure):
      _fields_ = [ ('a',ctypes.c_longlong) ]
    #
    btype = ctypes.c_int
    voidp = ctypes.c_void_p
    stp = ctypes.POINTER(St)
    stpvoid = ctypes.POINTER(None)
    arra1 = (ctypes.c_long *4)
    arra2 = (St *4)
    arra3 = (ctypes.POINTER(St) *4)
    charp = ctypes.c_char_p
    string = ctypes.CString
    fptr = type(ctypes.memmove)
    arra4 = (fptr*256)
    return locals()


class TestBasicFunctions(unittest.TestCase):
    """Tests basic haystack.utils functions on base types."""
    @classmethod
    def setUpClass(cls):
        # use the host ctypes without modif (except CString imported in model)
        for name,value in make_types().items():
            globals()[name] = value

    def setUp(self):
        self.tests = [btype, voidp, St, stp, arra1, arra2, arra3, charp, string, fptr, arra4, St2, SubSt2]

    def _testMe(self, fn, valids, invalids):
        for var in valids:
            self.assertTrue( fn( var ), var )
        for var in invalids:
            self.assertFalse( fn( var ), var )

    def test_isBasicType(self):
        valids = [btype]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isBasicType, valids, invalids)
        return 

    def test_isStructType(self):
        valids = [St, St2, SubSt2]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isStructType, valids, invalids)
        return 

    def test_isPointerType(self):
        valids = [voidp, stp, stpvoid, fptr, charp]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isPointerType, valids, invalids)
        return 

    def test_isVoidPointerType(self):
        valids = [voidp, stpvoid, charp]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isVoidPointerType, valids, invalids)
        return 

    def test_isFunctionType(self):
        valids = [fptr]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isFunctionType, valids, invalids)
        return 

    def test_isBasicTypeArray(self):
        valids = [arra1()]
        invalids = [ v for v in self.tests if v not in valids]
        invalids.extend([ arra2(), arra3(), arra4(), ] )
        for var in valids:
            self.assertTrue( utils.isBasicTypeArray( var ), var)
        for var in invalids:
            self.assertFalse( utils.isBasicTypeArray( var ), var )
        return 

    def test_isArrayType(self):
        valids = [arra1, arra2, arra3, arra4, ]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isArrayType, valids, invalids)
        return 

    def test_isCStringPointer(self):
        valids = [string ]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isCStringPointer, valids, invalids)
        return 

    def test_is_ctypes(self):
        valids = [St(), St2(), SubSt2()]
        #valids = [btype, voidp, stp, stpvoid, arra1, arra2, arra3, string, fptr, arra4 ]
        invalids = [ v for v in self.tests if v not in valids]
        self._testMe( utils.isCTypes, valids, invalids)
        return 


    def test_import(self):
        #''' Do not replace c_char_p '''
        from haystack import basicmodel
        self.assertEquals( ctypes.c_char_p.__name__ , 'c_char_p', 'c_char_p should not be changed')
        self.assertTrue( issubclass(ctypes.Structure, basicmodel.LoadableMembers) )
        self.assertTrue( issubclass(ctypes.Union, basicmodel.LoadableMembers) )
        self.assertIn( basicmodel.CString, basicmodel.__dict__.values() )


class TestBasicFunctions32(TestBasicFunctions):
    """Tests basic haystack.utils functions on base types for x32 arch."""
    def setUp(self):
        """Have to reload that at every test. classmethod will not work"""
        #self.tests = [btype, voidp, St, stp, arra1, arra2, arra3, charp, string, fptr, arra4, St2, SubSt2]
        TestBasicFunctions.setUp(self)
        # use the host ctypes with modif
        from haystack import types
        print 'A'
        ctypes = types.reload_ctypes(longsize=4,pointersize=4,longdoublesize=8)
        print 'B', self, ctypes
        import code
        code.interact(local=locals())
        for name,value in make_types().items():
            globals()[name] = value
        print self, ctypes

    def test_sizes(self):
        print arra1, ctypes.sizeof(ctypes.c_long)
        import code
        code.interact(local=locals())
        self.assertEquals( ctypes.sizeof(arra1), 4*4)
        return 

class TestBasicFunctions64(TestBasicFunctions):
    """Tests basic haystack.utils functions on base types for x64 arch."""
    def setUp(self):
        """Have to reload that at every test. classmethod will not work"""
        TestBasicFunctions.setUp(self)
        # use the host ctypes with modif
        from haystack import types
        ctypes = types.reload_ctypes(longsize=8,pointersize=8,longdoublesize=16)
        for name,value in make_types().items():
            globals()[name] = value
        #
        print self, ctypes
        
    def test_sizes(self):
        self.assertEquals( ctypes.sizeof(arra1), 4*8)
        return 


if __name__ == '__main__':
    unittest.main(verbosity=0)


