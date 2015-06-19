#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import struct
import operator
import os
import unittest
import pickle
import sys

from haystack import model
from haystack.reverse import context

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger('test_fieldtypes')

class TestField(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        #self.context3 = context.get_context('test/src/test-ctypes3.dump')
        self.context6 = context.get_context('test/src/test-ctypes6.32.dump')
        from haystack.reverse.heuristics import dsa
        self.dsa = dsa.DSASimple(self.context6.mappings)
        self.st = self.context6.listStructures()[0]
        
    def setUp(self):
        model.reset()
        pass

    def tearDown(self):
        pass
    
    def test_is_types(self):
        from haystack.reverse import fieldtypes
        #def __init__(self, astruct, offset, typename, size, isPadding):
        ptr = fieldtypes.PointerField(self.st,8, fieldtypes.FieldType.POINTER, 4, False)
        self.assertFalse(ptr.isString())
        self.assertTrue(ptr.isPointer())
        self.assertFalse(ptr.isZeroes())
        self.assertFalse(ptr.isArray())
        self.assertFalse(ptr.isInteger())
    
    

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
    logging.getLogger("structure").setLevel(level=logging.DEBUG)
    logging.getLogger("field").setLevel(level=logging.DEBUG)
    logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    #unittest.TextTestRunner(verbosity=2).run(suite)


