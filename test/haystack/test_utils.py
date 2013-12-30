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

import unittest

class TestHelpers(unittest.TestCase):
    """Tests helpers functions."""

    def test_formatAddress(self):
        from haystack import types
        types.reload_ctypes(8,8,16)
        x = utils.formatAddress(0x12345678)
        self.assertEquals('0x0000000012345678', x)
        # 32b
        types.reload_ctypes(4,4,8)
        x = utils.formatAddress(0x12345678)
        self.assertEquals('0x12345678', x)

    def test_unpackWord(self):
        from haystack import types
        # 64b
        types.reload_ctypes(8,8,16)
        one = b'\x01'+7*b'\x00'
        x = utils.unpackWord(one)
        self.assertEquals(x, 1)
        # 32b
        types.reload_ctypes(4,4,8)
        one32 = b'\x01'+3*b'\x00'
        x = utils.unpackWord(one32)
        self.assertEquals(x, 1)
        pass
        # endianness
        two32 = 3*b'\x00'+'\x02'
        x = utils.unpackWord(two32,'>')
        self.assertEquals(x, 2)
        pass


    def test_is_valid_address(self):
        #utils.is_valid_address(obj, mappings, structType=None):
        # FIXME requires mappings
        pass
    def test_is_valid_address_value(self):
        #utils.is_valid_address_value(addr, mappings, structType=None):
        # FIXME requires mappings
        pass
    def test_is_address_local(self):
        #utils.is_address_local(obj, structType=None):
        # FIXME requires memory_mapping
        pass

    def test_getaddress(self):
        """tests getaddress on host ctypes POINTER and haystack POINTER"""
        from haystack import types
        ctypes = types.reload_ctypes(8,8,16)
        class X(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long), #
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        self.assertEquals( ctypes.sizeof(X), 17) 
        i = X.from_buffer_copy(b'\xAA\xAA\xBB\xBB'+4*'\xBB'+8*'\x11'+'\xCC')
        a = utils.getaddress(i.p)
        self.assertEquals( ctypes.sizeof(i.p), 8) 
        self.assertNotEquals(a, 0)
        self.assertEquals(a, 0x1111111111111111) # 8*'\x11'
        # null pointer
        i = X.from_buffer_copy(b'\xAA\xAA\xBB\xBB'+4*'\xBB'+8*'\x00'+'\xCC')
        pnull = utils.getaddress(i.p)
        self.assertEquals( utils.getaddress(pnull), 0)

        # change arch, and retry
        ctypes = types.reload_ctypes(4,4,8)
        class Y(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        self.assertEquals( ctypes.sizeof(Y), 9) 
        i = Y.from_buffer_copy(b'\xAA\xAA\xBB\xBB'+4*'\x11'+'\xCC')
        a = utils.getaddress(i.p)
        self.assertEquals( ctypes.sizeof(i.p), 4) 
        self.assertNotEquals(a, 0)
        self.assertEquals(a, 0x11111111) # 4*'\x11'
        # null pointer
        i = Y.from_buffer_copy(b'\xAA\xAA\xBB\xBB'+4*'\x00'+'\xCC')
        pnull = utils.getaddress(i.p)
        self.assertEquals( utils.getaddress(pnull), 0)
        
        # non-pointer, and void null pointer
        ctypes = types.load_ctypes_default()
        i = ctypes.c_int(69)
        self.assertEquals( utils.getaddress(i), 0)
        pnull = ctypes.c_void_p(0)
        self.assertEquals( utils.getaddress(pnull), 0)

        pass

    def test_container_of(self):
        #utils.container_of(memberaddr, typ, membername):
        pass
    def test_offsetof(self):
        #utils.offsetof(typ, membername):
        pass
    def test_array2bytes_(self):
        #utils.array2bytes_(array, typ):
        pass
    def test_array2bytes(self):
        #utils.array2bytes(array):
        pass
    def test_bytes2array(self):
        #utils.bytes2array(bytes, typ):
        pass
    def test_pointer2bytes(self):
        #utils.pointer2bytes(attr,nbElement)
        pass

    def test_xrange(self):
        """tests home made xrange that handles big ints. 
        Not an issue in Py 3"""
        a=11111111111111111111111111111111111111111111111111111111111111111111111111111111111111
        b=a+10
        r = [x for x in utils.xrange(a,b)]
        r2 = []
        while a<b:
            r2.append(a)
            a+=1
        self.assertEquals(r,r2)



if __name__ == '__main__':
    unittest.main(verbosity=0)


