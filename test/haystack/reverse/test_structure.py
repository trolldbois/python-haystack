#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

import os

from haystack.reverse import context
from haystack.reverse import config
from haystack.reverse import structure
from haystack.reverse.heuristics import dsa
from haystack import dump_loader
import pointertypes

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger("test_structure")


class TestStructure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = 'test/src/test-ctypes3.32.dump'
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(cls.dumpname)
        finder = cls.memory_handler.get_heap_finder()
        heap = finder.get_heap_mappings()[0]
        heap_addr = heap.get_marked_heap_address()
        cls.context = context.get_context_for_address(cls.memory_handler, heap_addr)
        cls.target = cls.context.memory_handler.get_target_platform()
        cls.dsa = dsa.FieldReverser(cls.context.memory_handler)
        cls.pta = pointertypes.EnrichedPointerFields(cls.context.memory_handler)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        cls.context = None
        cls.target = None
        cls.dsa = None
        cls.pta = None
        return

    def setUp(self):
        return

    def tearDown(self):
        self.context.reset()
        return

    def test_decodeFields(self):
        for s in self.context.listStructures():
            self.dsa.analyze_fields(s)
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s.get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(s.get_pointer_fields()), 2)
            elif len(s) == 20:  # test3, 1 pointer on create
                # fields, no heuristic to detect medium sized int
                # TODO untyped of size < 8 == int * x
                # print s.toString()
                self.assertEqual(len(s.get_fields()), 3)  # discutable
                self.assertEqual(len(s.get_pointer_fields()), 1)
        return

    def test_resolvePointers(self):
        for s in self.context.listStructures():
            self.dsa.analyze_fields(s)
        for s in self.context.listStructures():
            self.pta.analyze_fields(s)
        self.assertTrue(True)  # test no error

    def test_resolvePointers2(self):
        for s in self.context.listStructures():
            self.dsa.analyze_fields(s)
            self.assertEqual(s.get_reverse_level(), 10)
        for s in self.context.listStructures():
            log.debug('RLEVEL: %d' % s.get_reverse_level())
            self.pta.analyze_fields(s)
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s.get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(s.get_pointer_fields()), 2)

    def test_reset(self):
        for s in self.context.listStructures():
            s.reset()
            if isinstance(s, structure.CacheWrapper):
                members = s.obj().__dict__
            else:
                members = s.__dict__
            for name, value in members.items():
                if name in ['_size', '_memory_handler', '_name', '_vaddr', '_target']:
                    self.assertNotIn(value, [None, False])
                elif name in ['_dirty', '_AnonymousRecord__address']:
                    self.assertTrue(value)
                elif name in ['_fields']:
                    self.assertEquals(value, list())
                elif name in ['dumpname']:
                    self.assertTrue(os.access(value, os.F_OK))
                else:
                    self.assertIn(value, [None, False], name + ' not resetted')


class TestStructure2(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = 'test/src/test-ctypes6.32.dump'
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(cls.dumpname)
        finder = cls.memory_handler.get_heap_finder()
        heap = finder.get_heap_mappings()[0]
        heap_addr = heap.get_marked_heap_address()
        cls.context = context.get_context_for_address(cls.memory_handler, heap_addr)
        cls.target = cls.context.memory_handler.get_target_platform()
        cls.dsa = dsa.FieldReverser(cls.context.memory_handler)
        cls.pta = pointertypes.EnrichedPointerFields(cls.context.memory_handler)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        cls.context = None
        cls.target = None
        cls.dsa = None
        cls.pta = None
        return

    def setUp(self):
        return

    def tearDown(self):
        self.context.reset()
        return

    def test_string_overlap(self):
        for s in self.context.listStructures():
            # s.resolvePointers()
            self.dsa.analyze_fields(s)
            log.debug(s.to_string())
        self.assertTrue(True)  # test no error


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger("test_structure").setLevel(logging.DEBUG)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main(verbosity=2)
