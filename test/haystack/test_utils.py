# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""
import haystack.model

# init ctypes with a controlled type size
import ctypes
import logging
import unittest
import os

from haystack import model
from haystack import utils
from haystack import types
from haystack import target
from haystack.mappings.process import make_process_memory_handler, make_local_memory_handler


class TestHelpers(unittest.TestCase):

    """Tests helpers functions."""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_is_address_local(self):
        my_target = target.TargetPlatform.make_target_platform_local()
        my_ctypes = my_target.get_target_ctypes()
        my_utils = my_target.get_target_ctypes_utils()
        ctypes5_gen64 = haystack.model.import_module_for_target_ctypes("test.src.ctypes5_gen64", my_ctypes)
        # kinda chicken and egg here...

        # one call
        mappings = make_local_memory_handler()
        m = mappings.get_mappings()[0]

        # struct a - basic types
        s = ctypes.sizeof(ctypes5_gen64.struct_a)

        a = ctypes5_gen64.struct_a.from_address(m.start)
        pa = my_ctypes.c_void_p(m.start)
        ptr_a = my_ctypes.POINTER(ctypes5_gen64.struct_a)(a)

        b = ctypes5_gen64.struct_a.from_address(m.end - s)
        pb = my_ctypes.c_void_p(m.end - s)
        ptr_b = my_ctypes.POINTER(ctypes5_gen64.struct_a)(b)

        c = ctypes5_gen64.struct_a.from_address(m.end - 1)
        pc = my_ctypes.c_void_p(m.end - 1)
        ptr_c = my_ctypes.POINTER(ctypes5_gen64.struct_a)(c)

        self.assertTrue(my_utils.is_address_local(pa, structType=None))
        self.assertTrue(
            my_utils.is_address_local(
                pa,
                structType=ctypes5_gen64.struct_a))
        self.assertTrue(my_utils.is_address_local(ptr_a, structType=None))
        self.assertTrue(
            my_utils.is_address_local(
                ptr_a,
                structType=ctypes5_gen64.struct_a))

        self.assertTrue(my_utils.is_address_local(pb, structType=None))
        self.assertTrue(
            my_utils.is_address_local(
                pb,
                structType=ctypes5_gen64.struct_a))
        self.assertTrue(my_utils.is_address_local(ptr_b, structType=None))
        self.assertTrue(
            my_utils.is_address_local(
                ptr_b,
                structType=ctypes5_gen64.struct_a))

        self.assertTrue(my_utils.is_address_local(pc, structType=None))
        self.assertFalse(
            my_utils.is_address_local(
                pc,
                structType=ctypes5_gen64.struct_a))
        self.assertTrue(my_utils.is_address_local(ptr_c, structType=None))
        self.assertFalse(
            my_utils.is_address_local(
                ptr_c,
                structType=ctypes5_gen64.struct_a))

    def test_pointer2bytes(self):
        my_target = target.TargetPlatform.make_target_platform_local()
        my_ctypes = my_target.get_target_ctypes()
        my_utils = my_target.get_target_ctypes_utils()

        class X(my_ctypes.Structure):
            _fields_ = [('a', my_ctypes.c_long)]
        nb = 3
        x = (nb * X)()
        x[2].a = 42
        ptr = my_ctypes.POINTER(X)(x[0])
        bytes_x = my_utils.pointer2bytes(ptr, nb)
        self.assertEqual(len(bytes_x), my_ctypes.sizeof(x))
        self.assertEqual(
            bytes_x,
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00*\x00\x00\x00\x00\x00\x00\x00')
        pass

    def test_formatAddress(self):
        my_utils64 = utils.Utils(types.build_ctypes_proxy(8, 8, 16))
        my_utils32 = utils.Utils(types.build_ctypes_proxy(4, 4, 8))

        x = my_utils64.formatAddress(0x12345678)
        self.assertEqual(b'0x0000000012345678', x)
        # 32b
        x = my_utils32.formatAddress(0x12345678)
        self.assertEqual(b'0x12345678', x)

    def test_unpackWord(self):
        # 64b
        my_utils = utils.Utils(types.build_ctypes_proxy(8, 8, 16))

        one = b'\x01' + 7 * b'\x00'
        x = my_utils.unpackWord(one)
        self.assertEqual(x, 1)
        # 32b
        my_utils = utils.Utils(types.build_ctypes_proxy(4, 4, 8))
        one32 = b'\x01' + 3 * b'\x00'
        x = my_utils.unpackWord(one32)
        self.assertEqual(x, 1)
        pass
        # endianness
        two32 = 3 * b'\x00' + b'\x02'
        x = my_utils.unpackWord(two32, '>')
        self.assertEqual(x, 2)
        pass

    def test_get_pointee_address(self):
        """tests get_pointee_address on host ctypes POINTER and haystack POINTER"""
        my_ctypes = types.build_ctypes_proxy(8, 8, 16)
        my_utils = utils.Utils(my_ctypes)

        class X(my_ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        self.assertEqual(my_ctypes.sizeof(X), 17)
        i = X.from_buffer_copy(
            b'\xAA\xAA\xBB\xBB' +
            4 *
            b'\xBB' +
            8 *
            b'\x11' +
            b'\xCC')
        a = my_utils.get_pointee_address(i.p)
        self.assertEqual(my_ctypes.sizeof(i.p), 8)
        self.assertNotEquals(a, 0)
        self.assertEqual(a, 0x1111111111111111)  # 8*'\x11'
        # null pointer
        i = X.from_buffer_copy(
            b'\xAA\xAA\xBB\xBB' +
            4 *
            b'\xBB' +
            8 *
            b'\x00' +
            b'\xCC')
        pnull = my_utils.get_pointee_address(i.p)
        self.assertEquals (my_utils.get_pointee_address(pnull), 0)

        # change arch, and retry
        my_ctypes = types.build_ctypes_proxy(4, 4, 8)

        class Y(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        self.assertEqual(my_ctypes.sizeof(Y), 9)
        i = Y.from_buffer_copy(b'\xAA\xAA\xBB\xBB' + 4 * b'\x11' + b'\xCC')
        a = my_utils.get_pointee_address(i.p)
        self.assertEqual(my_ctypes.sizeof(i.p), 4)
        self.assertNotEquals(a, 0)
        self.assertEqual(a, 0x11111111)  # 4*'\x11'
        # null pointer
        i = Y.from_buffer_copy(b'\xAA\xAA\xBB\xBB' + 4 * b'\x00' + b'\xCC')
        pnull = my_utils.get_pointee_address(i.p)
        self.assertEquals (my_utils.get_pointee_address(pnull), 0)

        # non-pointer, and void null pointer
        my_ctypes = types.load_ctypes_default()
        i = my_ctypes.c_int(69)
        self.assertEquals (my_utils.get_pointee_address(i), 0)
        pnull = my_ctypes.c_void_p(0)
        self.assertEquals (my_utils.get_pointee_address(pnull), 0)

        pass

    def test_offsetof(self):
        """returns the offset of a member fields in a record"""
        my_ctypes = types.build_ctypes_proxy(4, 4, 8)
        my_utils = utils.Utils(my_ctypes)

        class Y(my_ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        o = my_utils.offsetof(Y, 'b')
        self.assertEqual(o, 8)

        my_ctypes = types.build_ctypes_proxy(8, 8, 16)
        my_utils = utils.Utils(my_ctypes)

        class X(my_ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        o = my_utils.offsetof(X, 'b')
        self.assertEqual(o, 16)

        class X2(my_ctypes.Union):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        o = my_utils.offsetof(X2, 'b')
        self.assertEqual(o, 0)
        pass

    def test_container_of(self):
        """From a pointer to a member, returns the parent struct"""
        # depends on offsetof
        my_ctypes = types.build_ctypes_proxy(8, 8, 16)
        my_utils = utils.Utils(my_ctypes)

        class X(my_ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        x = X()
        x.a = 1
        x.b = 2
        addr_b = my_ctypes.addressof(x) + 16  # a + p
        o = my_utils.container_of(addr_b, X, 'b')
        self.assertEqual(my_ctypes.addressof(o), my_ctypes.addressof(x))

        my_ctypes = types.build_ctypes_proxy(4, 4, 8)
        my_utils = utils.Utils(my_ctypes)

        class Y(ctypes.Structure):
            _pack_ = True
            _fields_ = [('a', my_ctypes.c_long),
                        ('p', my_ctypes.POINTER(my_ctypes.c_int)),
                        ('b', my_ctypes.c_ubyte)]
        y = Y()
        y.a = 1
        y.b = 2
        addr_b = my_ctypes.addressof(y) + 8  # a + p
        o = my_utils.container_of(addr_b, Y, 'b')
        self.assertEqual(my_ctypes.addressof(o), my_ctypes.addressof(y))
        pass

    def test_array2bytes(self):
        """array to bytes"""
        my_ctypes = types.build_ctypes_proxy(4, 4, 8)
        my_utils = utils.Utils(my_ctypes)

        a = (my_ctypes.c_long * 12)(4, 1, 1, 1, 2)
        x = my_utils.array2bytes(a)
        self.assertEqual(b'\x04' + 3 * b'\x00' +
                          b'\x01' + 3 * b'\x00' +
                          b'\x01' + 3 * b'\x00' +
                          b'\x01' + 3 * b'\x00' +
                          b'\x02' + 3 * b'\x00' +
                          7 * 4 * b'\x00', x)

        my_ctypes = types.build_ctypes_proxy(8, 8, 16)
        my_utils = utils.Utils(my_ctypes)

        a = (my_ctypes.c_long * 12)(4, 1, 1, 1, 2)
        x = my_utils.array2bytes(a)
        self.assertEqual(b'\x04' + 7 * b'\x00' +
                          b'\x01' + 7 * b'\x00' +
                          b'\x01' + 7 * b'\x00' +
                          b'\x01' + 7 * b'\x00' +
                          b'\x02' + 7 * b'\x00' +
                          7 * 8 * b'\x00', x)

        a = (my_ctypes.c_char * 12).from_buffer_copy(b'1234567890AB')
        x = my_utils.array2bytes(a)
        self.assertEqual(b'1234567890AB', x)

        # mimics what ctypes gives us on memory loading.
        a = b'1234567890AB'
        x = my_utils.array2bytes(a)
        self.assertEqual(b'1234567890AB', x)
        pass

    def test_bytes2array(self):
        """bytes to ctypes array"""
        my_ctypes = types.build_ctypes_proxy(4, 4, 8)
        my_utils = utils.Utils(my_ctypes)

        bytes = 4 * b'\xAA' + 4 * b'\xBB' + 4 * b'\xCC' + \
            4 * b'\xDD' + 4 * b'\xEE' + 4 * b'\xFF'
        array = my_utils.bytes2array(bytes, my_ctypes.c_ulong)
        self.assertEqual(array[0], 0xAAAAAAAA)
        self.assertEqual(len(array), 6)

        my_ctypes = types.build_ctypes_proxy(8, 8, 16)
        my_utils = utils.Utils(my_ctypes)

        bytes = 4 * b'\xAA' + 4 * b'\xBB' + 4 * b'\xCC' + \
            4 * b'\xDD' + 4 * b'\xEE' + 4 * b'\xFF'
        array = my_utils.bytes2array(bytes, my_ctypes.c_ulong)
        self.assertEqual(array[0], 0xBBBBBBBBAAAAAAAA)
        self.assertEqual(len(array), 3)
        pass

    def test_get_subtype(self):
        my_ctypes = types.load_ctypes_default()
        my_utils = utils.Utils(my_ctypes)

        class X(my_ctypes.Structure):
            _fields_ = [('p', my_ctypes.POINTER(my_ctypes.c_long))]
        PX = my_ctypes.POINTER(X)
        self.assertEqual(my_utils.get_subtype(PX), X)

        my_ctypes = types.build_ctypes_proxy(4, 4, 8)  # different arch

        class Y(my_ctypes.Structure):
            _fields_ = [('p', my_ctypes.POINTER(my_ctypes.c_long))]
        PY = my_ctypes.POINTER(Y)
        self.assertEqual(my_utils.get_subtype(PY), Y)

    def test_xrange(self):
        """tests home made xrange that handles big ints.
        Not an issue in Py 3"""
        a = 11111111111111111111111111111111111111111111111111111111111111111111111111111111111111
        b = a + 10
        r = [x for x in utils.xrange(a, b)]
        r2 = []
        while a < b:
            r2.append(a)
            a += 1
        self.assertEqual(r, r2)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)
