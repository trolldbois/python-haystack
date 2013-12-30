#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.types."""

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2013 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

# init ctypes with a controlled type size
from haystack import model
from haystack import types

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
    double = ctypes.c_longdouble
    return locals()


class TestSizes(unittest.TestCase):
    """Tests sizes after ctypes changes."""

    def test_reset_ctypes(self):
        """Test if reset gives the original types"""
        global ctypes
        ctypes = types.reload_ctypes(4,4,8)
        proxy = ctypes
        for name,value in make_types().items():
            globals()[name] = value
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        
        ctypes = types.reset_ctypes()
        # no CString.
        self.assertRaises(AttributeError, make_types)
        self.assertIn('ctypes','%s'%(ctypes) )
        self.assertFalse( hasattr(ctypes,'proxy') )
        return 

    def test_load_ctypes_default(self):
        """Test if the default proxy works"""
        global ctypes
        ctypes = types.reload_ctypes(4,4,8)
        self.assertTrue(ctypes.proxy)
        # test
        ctypes = types.load_ctypes_default()
        self.assertTrue(ctypes.proxy)
        for name,value in make_types().items():
            globals()[name] = value
        # default ctypes should be similar to host ctypes.
        self.assertEquals( ctypes.sizeof(arra1), 4*ctypes.sizeof(ctypes.get_real_ctypes_type('c_long')) )
        self.assertEquals( ctypes.sizeof(stp), ctypes.sizeof(ctypes.get_real_ctypes_type('c_void_p')) )
        self.assertEquals( ctypes.sizeof(arra1), 4*ctypes.sizeof(ctypes.c_long) )
        self.assertEquals( ctypes.sizeof(stp), ctypes.sizeof(ctypes.c_void_p) )
        return 

    def test_reload_ctypes(self):
        """Tests loading of specific arch ctypes."""
        global ctypes
        ctypes = types.reload_ctypes(4,4,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(4,8,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(8,4,8)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        # other arch
        ctypes = types.reload_ctypes(8,4,16)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 16 )

        # other arch        
        self.assertRaises(NotImplementedError, types.reload_ctypes, 16,8,16) 
        return 

    def test_set_ctypes(self):
        """Test reloading of previous defined arch-ctypes."""
        global ctypes
        x32 = types.reload_ctypes(4,4,8)
        x64 = types.reload_ctypes(8,8,16)
        win = types.reload_ctypes(8,8,8)
        ctypes = types.reset_ctypes()
        
        ctypes = types.set_ctypes(x32)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x32 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        ctypes = types.set_ctypes(x64)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x64 )
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 16 )

        ctypes = types.set_ctypes(win)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, win )
        self.assertEquals( ctypes.sizeof(arra1), 4*8 )
        self.assertEquals( ctypes.sizeof(stp), 8 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        ctypes = types.set_ctypes(x32)
        for name,value in make_types().items():
            globals()[name] = value
        self.assertTrue(ctypes.proxy)
        self.assertEquals( ctypes, x32 )
        self.assertEquals( ctypes.sizeof(arra1), 4*4 )
        self.assertEquals( ctypes.sizeof(stp), 4 )
        self.assertEquals( ctypes.sizeof(double), 8 )

        return 


if __name__ == '__main__':
    unittest.main(verbosity=0)


