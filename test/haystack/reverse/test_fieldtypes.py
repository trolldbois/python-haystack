#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

from haystack.reverse import context
from haystack.reverse import config
from haystack.reverse.heuristics import dsa
from haystack.reverse import fieldtypes

log = logging.getLogger('test_fieldtypes')


class TestField(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        #self.context3 = context.get_context('test/src/test-ctypes3.dump')
        cls.dumpname = 'test/src/test-ctypes6.32.dump'
        config.remove_cache_folder(cls.dumpname)
        cls.context6 = context.get_context(cls.dumpname)
        cls.dsa = dsa.DSASimple(cls.context6.memory_handler)
        cls.st = cls.context6.listStructures()[0]

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_is_types(self):
        # def __init__(self, astruct, offset, typename, size, isPadding):
        ptr = fieldtypes.PointerField(
            self.st,
            8,
            fieldtypes.FieldType.POINTER,
            4,
            False)
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
    # unittest.TextTestRunner(verbosity=2).run(suite)
