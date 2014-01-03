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
from haystack import types

import logging
import unittest

class TestHelpers(unittest.TestCase):
    """Tests helpers functions."""

    @unittest.skip('FIXME requires mappings')
    def test_is_valid_address(self):
        #utils.is_valid_address(obj, mappings, structType=None):
        # FIXME requires mappings
        pass

    @unittest.skip('FIXME requires mappings')
    def test_is_valid_address_value(self):
        #utils.is_valid_address_value(addr, mappings, structType=None):
        # FIXME requires mappings
        pass

    @unittest.skip('FIXME: requires memory_mapping')
    def test_is_address_local(self):
        #utils.is_address_local(obj, structType=None):
        # FIXME requires memory_mapping
        pass

    @unittest.skip('FIXME: requires is_address_local')
    def test_pointer2bytes(self):
        #utils.pointer2bytes(attr,nbElement)
        # FIXME: requires is_address_local
        ctypes = types.load_ctypes_default()
        class X(ctypes.Structure):
            _fields_ = [('a',ctypes.c_long)]
        x = (8*X)()
        ptr = ctypes.POINTER(X)(x[0])
        new_x = utils.pointer2bytes(ptr, 8)
        self.assertEquals(x, new_x)
        pass


    def test_formatAddress(self):
        types.reload_ctypes(8,8,16)
        x = utils.formatAddress(0x12345678)
        self.assertEquals('0x0000000012345678', x)
        # 32b
        types.reload_ctypes(4,4,8)
        x = utils.formatAddress(0x12345678)
        self.assertEquals('0x12345678', x)

    def test_unpackWord(self):
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

    def test_getaddress(self):
        """tests getaddress on host ctypes POINTER and haystack POINTER"""
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

    def test_offsetof(self):
        """returns the offset of a member fields in a record"""
        ctypes = types.reload_ctypes(4,4,8)
        class Y(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        o = utils.offsetof(Y, 'b')
        self.assertEquals( o, 8)

        ctypes = types.reload_ctypes(8,8,16)
        class X(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        o = utils.offsetof(X, 'b')
        self.assertEquals( o, 16)

        class X2(ctypes.Union):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        o = utils.offsetof(X2, 'b')
        self.assertEquals( o, 0)
        pass

    def test_container_of(self):
        """From a pointer to a member, returns the parent struct"""
        # depends on offsetof
        ctypes = types.reload_ctypes(8,8,16)
        class X(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        x = X()
        x.a = 1
        x.b = 2
        addr_b = ctypes.addressof(x) + 16 # a + p
        o = utils.container_of(addr_b, X, 'b')
        self.assertEquals( ctypes.addressof(o), ctypes.addressof(x))

        ctypes = types.reload_ctypes(4,4,8)
        class Y(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a',ctypes.c_long),
                ('p',ctypes.POINTER(ctypes.c_int)),
                ('b', ctypes.c_ubyte)]
        y = Y()
        y.a = 1
        y.b = 2
        addr_b = ctypes.addressof(y) + 8 # a + p
        o = utils.container_of(addr_b, Y, 'b')
        self.assertEquals( ctypes.addressof(o), ctypes.addressof(y))
        pass

    def test_array2bytes(self):
        """array to bytes"""
        ctypes = types.reload_ctypes(4,4,8)
        a = (ctypes.c_long*12)(4,1,1,1,2)
        x = utils.array2bytes(a)
        self.assertEquals(b'\x04'+3*b'\x00'+
                          b'\x01'+3*b'\x00'+
                          b'\x01'+3*b'\x00'+
                          b'\x01'+3*b'\x00'+
                          b'\x02'+3*b'\x00'+
                          7*4*'\x00', x)

        ctypes = types.reload_ctypes(8,8,16)
        a = (ctypes.c_long*12)(4,1,1,1,2)
        x = utils.array2bytes(a)
        self.assertEquals(b'\x04'+7*b'\x00'+
                          b'\x01'+7*b'\x00'+
                          b'\x01'+7*b'\x00'+
                          b'\x01'+7*b'\x00'+
                          b'\x02'+7*b'\x00'+
                          7*8*'\x00', x)

        a = (ctypes.c_char*12).from_buffer_copy('1234567890AB')
        x = utils.array2bytes(a)
        self.assertEquals(b'1234567890AB', x)

        # mimics what ctypes gives us on memory loading.
        a = b'1234567890AB' 
        x = utils.array2bytes(a)
        self.assertEquals(b'1234567890AB', x)
        pass

    def test_bytes2array(self):
        """bytes to ctypes array"""
        ctypes = types.reload_ctypes(4,4,8)
        bytes = 4*b'\xAA'+4*b'\xBB'+4*b'\xCC'+4*b'\xDD'+4*b'\xEE'+4*b'\xFF'
        array = utils.bytes2array(bytes, ctypes.c_ulong)
        self.assertEquals(array[0], 0xAAAAAAAA)
        self.assertEquals(len(array), 6)

        ctypes = types.reload_ctypes(8,8,16)
        bytes = 4*b'\xAA'+4*b'\xBB'+4*b'\xCC'+4*b'\xDD'+4*b'\xEE'+4*b'\xFF'
        array = utils.bytes2array(bytes, ctypes.c_ulong)
        self.assertEquals(array[0], 0xBBBBBBBBAAAAAAAA)
        self.assertEquals(len(array), 3)
        pass

    def test_get_subtype(self):
        ctypes = types.reset_ctypes()
        class X(ctypes.Structure):
            _fields_ = [('p',ctypes.POINTER(ctypes.c_long))]
        PX = ctypes.POINTER(X)
        self.assertEquals(utils.get_subtype(PX), X)
        
        ctypes = types.reload_ctypes(4,4,8) # different arch
        class Y(ctypes.Structure):
            _fields_ = [('p',ctypes.POINTER(ctypes.c_long))]
        PY = ctypes.POINTER(Y)
        self.assertEquals(utils.get_subtype(PY), Y)

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
    logging.basicConfig(level=logging.WARNING)
    unittest.main(verbosity=2)


