#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import dump_loader
from haystack import utils
from haystack.outputters import text
from haystack.outputters import python

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
        model.reset()
        self.mappings = dump_loader.load('test/src/test-ctypes5.32.dump')
        self._load_offsets_values('test/src/test-ctypes5.32.dump')

    def tearDown(self):
        from haystack import model
        model.reset()
        self.mappings = None
        pass

    def test_complex_text(self):
        from test.src import ctypes5_gen32
        model.registerModule(ctypes5_gen32)
        # struct a - basic types
        offset = self.offsets['struct_d'][0]
        m = self.mappings.get_mapping_for_address(offset)
        d = m.readStruct(offset, ctypes5_gen32.struct_d)
        ret = d.loadMembers(self.mappings, 10)
        self.assertTrue(ret)
        parser = text.RecursiveTextOutputter(self.mappings)
        out = parser.parse(d)
        # should not fail
        x = eval(out)

        self.assertEquals(len(x.keys()), 15)  # 14 + padding
        self.assertEquals(self.values['struct_d.a'], hex(x['a']))
        self.assertEquals(len(x['b'].keys()), 9)
        self.assertEquals(len(x['b2'].keys()), 8)
        self.assertEquals(int(self.values['struct_d.b.e']), x['b']['e'])
        self.assertEquals(int(self.values['struct_d.b2.e']), x['b2']['e'])

        for i in range(9):
            self.assertEquals(
                int(self.values['struct_d.c[%d].a' % (i)]), x['c'][i]['a'])
            self.assertEquals(
                int(self.values['struct_d.f[%d]' % (i)]), x['f'][i])
        self.assertEquals(int(self.values['struct_d.e']), x['e'])
        self.assertEquals(str(self.values['struct_d.i']), x['i'])
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
