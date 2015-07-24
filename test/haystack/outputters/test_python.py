#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import dump_loader
from haystack.outputters import python
from test.haystack import SrcTests

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class TestToPyObject(SrcTests):

    """Basic types"""

    def setUp(self):
        self.memory_handler = dump_loader.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
        sys.path.append('test/src/')
        my_model = self.memory_handler.get_model()
        self.ctypes5_gen32 = my_model.import_module("ctypes5_gen32")
        my_model.build_python_class_clones(self.ctypes5_gen32)


    def tearDown(self):
        self.memory_handler = None
        self.ctypes5_gen32 = None
        sys.path.remove('test/src/')

    def test_complex(self):
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        d = m.read_struct(offset, self.ctypes5_gen32.struct_d)
        ret = d.load_members(self.memory_handler, 10)
        self.assertTrue(ret)

        import ctypes
        self.assertEquals(int(self.sizes['struct_d']), ctypes.sizeof(d))

        parser = python.PythonOutputter(self.memory_handler)
        obj = parser.parse(d)

        self.assertEquals(d.a.value, self.offsets['struct_d'][0])
        self.assertEquals(d.b.value, self.offsets['struct_d.b'][0])
        self.assertEquals(d.b2.value, self.offsets['struct_d.b2'][0])
        for i in range(9):
            self.assertEquals(
                int(self.values['struct_d.c[%d].a' % i]), obj.c[i].a)
            self.assertEquals(
                int(self.values['struct_d.f[%d]' % i]), obj.f[i])
        self.assertEquals(int(self.values['struct_d.e']), obj.e)
        self.assertEquals(str(self.values['struct_d.i']), obj.i)

        return

    def test_basic_types(self):
        # struct a - basic types
        offset = self.offsets['struct_a'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        a = m.read_struct(offset, self.ctypes5_gen32.struct_a)
        ret = a.load_members(self.memory_handler, 10)
        self.assertTrue(ret)
        import ctypes
        self.assertEquals(int(self.sizes['struct_a']), ctypes.sizeof(a))

        parser = python.PythonOutputter(self.memory_handler)
        a = parser.parse(a)

        self.assertEquals(int(self.values['struct_a.a']), a.a)
        self.assertEquals(int(self.values['struct_a.b']), a.b)
        self.assertEquals(int(self.values['struct_a.c']), a.c)
        self.assertEquals(int(self.values['struct_a.d']), a.d)
        self.assertEquals(int(self.values['struct_a.e']), a.e)
        self.assertEquals(float(self.values['struct_a.f']), a.f)
        self.assertEquals(float(self.values['struct_a.g']), a.g)
        self.assertEquals(float(self.values['struct_a.h']), a.h)

        offset = self.offsets['union_au'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        au = m.read_struct(offset, self.ctypes5_gen32.union_au)
        ret = au.load_members(self.memory_handler, 10)
        self.assertTrue(ret)
        au = parser.parse(au)
        self.assertEquals(int(self.values['union_au.d']), au.d)
        self.assertEquals(float(self.values['union_au.g']), au.g)
        self.assertEquals(float(self.values['union_au.h']), au.h)

        return

    def test_basic_signed_types(self):
        # struct a - basic types
        offset = self.offsets['union_b'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        b = m.read_struct(offset, self.ctypes5_gen32.union_b)
        ret = b.load_members(self.memory_handler, 10)
        self.assertTrue(ret)

        parser = python.PythonOutputter(self.memory_handler)
        b = parser.parse(b)

        self.assertEquals(int(self.values['union_b.a']), b.a)
        self.assertEquals(int(self.values['union_b.b']), b.b)
        self.assertEquals(int(self.values['union_b.c']), b.c)
        self.assertEquals(int(self.values['union_b.d']), b.d)
        self.assertEquals(int(self.values['union_b.e']), b.e)
        # char 251
        self.assertEquals((self.values['union_b.g']), b.g)

        return

    def test_bitfield(self):
        # struct a - basic types
        offset = self.offsets['struct_c'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        c = m.read_struct(offset, self.ctypes5_gen32.struct_c)
        ret = c.load_members(self.memory_handler, 10)
        self.assertTrue(ret)

        import ctypes
        self.assertEquals(int(self.sizes['struct_c']), ctypes.sizeof(c))

        parser = python.PythonOutputter(self.memory_handler)
        c = parser.parse(c)

        self.assertEquals(int(self.values['struct_c.a1']), c.a1)
        self.assertEquals(int(self.values['struct_c.b1']), c.b1)
        self.assertEquals(int(self.values['struct_c.c1']), c.c1)
        self.assertEquals(int(self.values['struct_c.d1']), c.d1)
        self.assertEquals(str(self.values['struct_c.a2']), c.a2)
        self.assertEquals(int(self.values['struct_c.b2']), c.b2)
        self.assertEquals(int(self.values['struct_c.c2']), c.c2)
        self.assertEquals(int(self.values['struct_c.d2']), c.d2)
        self.assertEquals(int(self.values['struct_c.h']), c.h)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
