#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import sys
import unittest

from haystack.outputters import python
from haystack.search import api
from mappings import folder
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
        self.memory_handler = folder.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')
        sys.path.append('test/src/')
        my_model = self.memory_handler.get_model()
        self.ctypes5_gen32 = my_model.import_module("ctypes5_gen32")
        my_model.build_python_class_clones(self.ctypes5_gen32)

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.ctypes5_gen32 = None
        sys.path.remove('test/src/')

    def test_complex(self):
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        my_ctypes = self.memory_handler.get_target_platform().get_target_ctypes()
        d, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.struct_d, offset)
        self.assertTrue(validated)

        self.assertEqual(int(self.sizes['struct_d']), my_ctypes.sizeof(d))

        parser = python.PythonOutputter(self.memory_handler)
        obj = parser.parse(d)
        # check Ctypes values too
        self.assertEqual(d.a.value, self.offsets['struct_d'][0])
        self.assertEqual(d.b.value, self.offsets['struct_d.b'][0])
        self.assertEqual(d.b2.value, self.offsets['struct_d.b2'][0])

        # check python calues
        for i in range(9):
            self.assertEqual(
                int(self.values['struct_d.c[%d].a' % i]), obj.c[i].a)
            self.assertEqual(
                int(self.values['struct_d.f[%d]' % i]), obj.f[i])
        self.assertEqual(int(self.values['struct_d.e']), obj.e)
        self.assertEqual(self.values['struct_d.i'], obj.i)

        return

    def test_basic_types(self):
        # struct a - basic types
        offset = self.offsets['struct_a'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        my_ctypes = self.memory_handler.get_target_platform().get_target_ctypes()
        ret, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.struct_a, offset)
        self.assertTrue(validated)

        self.assertEqual(int(self.sizes['struct_a']), my_ctypes.sizeof(ret))

        parser = python.PythonOutputter(self.memory_handler)
        a = parser.parse(ret)

        self.assertEqual(int(self.values['struct_a.a']), a.a)
        self.assertEqual(int(self.values['struct_a.b']), a.b)
        self.assertEqual(int(self.values['struct_a.c']), a.c)
        self.assertEqual(int(self.values['struct_a.d']), a.d)
        self.assertEqual(int(self.values['struct_a.e']), a.e)
        self.assertEqual(float(self.values['struct_a.f']), a.f)
        self.assertEqual(float(self.values['struct_a.g']), a.g)
        self.assertEqual(float(self.values['struct_a.h']), a.h)

        offset = self.offsets['union_au'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        au, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.union_au, offset)
        self.assertTrue(validated)
        au = parser.parse(au)
        self.assertEqual(int(self.values['union_au.d']), au.d)
        self.assertEqual(float(self.values['union_au.g']), au.g)
        self.assertEqual(float(self.values['union_au.h']), au.h)

        return

    def test_basic_signed_types(self):
        # union b - basic types
        offset = self.offsets['union_b'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        my_ctypes = self.memory_handler.get_target_platform().get_target_ctypes()
        ret, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.union_b, offset)
        self.assertTrue(ret)

        parser = python.PythonOutputter(self.memory_handler)
        b = parser.parse(ret)

        self.assertEqual(int(self.values['union_b.a']), b.a)
        self.assertEqual(int(self.values['union_b.b']), b.b)
        self.assertEqual(int(self.values['union_b.c']), b.c)
        self.assertEqual(int(self.values['union_b.d']), b.d)
        self.assertEqual(int(self.values['union_b.e']), b.e)
        # char 251
        self.assertEqual((self.values['union_b.g']), b.g)

        return

    def test_bitfield(self):
        # struct a - basic types
        offset = self.offsets['struct_c'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        my_ctypes = self.memory_handler.get_target_platform().get_target_ctypes()
        c, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.struct_c, offset)
        self.assertTrue(validated)
        self.assertEqual(int(self.sizes['struct_c']), my_ctypes.sizeof(c))

        parser = python.PythonOutputter(self.memory_handler)
        c = parser.parse(c)

        self.assertEqual(int(self.values['struct_c.a1']), c.a1)
        self.assertEqual(int(self.values['struct_c.b1']), c.b1)
        self.assertEqual(int(self.values['struct_c.c1']), c.c1)
        self.assertEqual(int(self.values['struct_c.d1']), c.d1)
        # should be 'A' but is 65 because of bitfield
        #self.assertEqual(self.values['struct_c.a2'], c.a2)
        self.assertEqual(ord(self.values['struct_c.a2']), c.a2)
        self.assertEqual(int(self.values['struct_c.b2']), c.b2)
        self.assertEqual(int(self.values['struct_c.c2']), c.c2)
        self.assertEqual(int(self.values['struct_c.d2']), c.d2)
        self.assertEqual(int(self.values['struct_c.h']), c.h)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
