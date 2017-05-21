#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack.search import api
from haystack import dump_loader
from haystack.outputters import text
from test.haystack import SrcTests

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


class TestTextOutput(SrcTests):

    """Basic types"""

    def setUp(self):
        self.memory_handler = dump_loader.load('test/src/test-ctypes5.32.dump')
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

    def test_complex_text(self):
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.memory_handler.get_mapping_for_address(offset)
        # d = m.read_struct(offset, self.ctypes5_gen32.struct_d)
        results, validated = api.load_record(self.memory_handler, self.ctypes5_gen32.struct_d, offset)

        self.assertTrue(results)
        parser = text.RecursiveTextOutputter(self.memory_handler)
        out = parser.parse(results)
        # should not fail
        x = eval(out)

        self.assertEqual(len(x.keys()), 15)  # 14 + padding
        self.assertEqual(self.values['struct_d.a'], hex(x['a']))
        self.assertEqual(len(x['b'].keys()), 9)
        self.assertEqual(len(x['b2'].keys()), 8)
        self.assertEqual(int(self.values['struct_d.b.e']), x['b']['e'])
        self.assertEqual(int(self.values['struct_d.b2.e']), x['b2']['e'])

        for i in range(9):
            self.assertEqual(
                int(self.values['struct_d.c[%d].a' % (i)]), x['c'][i]['a'])
            self.assertEqual(
                int(self.values['struct_d.f[%d]' % (i)]), x['f'][i])
        self.assertEqual(int(self.values['struct_d.e']), x['e'])
        self.assertEqual(str(self.values['struct_d.i']), x['i'])
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
