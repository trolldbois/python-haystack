#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

import os

from haystack.reverse import context
from haystack.reverse import config
from haystack.reverse import structure
from haystack.reverse import fieldtypes
from haystack.reverse.heuristics import dsa
from haystack.reverse.heuristics import pointertypes
from haystack import dump_loader

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
        heap_walker = finder.list_heap_walkers()[0]
        heap_addr = heap_walker.get_heap_address()
        cls.context = context.get_context_for_address(cls.memory_handler, heap_addr)
        cls.target = cls.context.memory_handler.get_target_platform()
        cls.dsa = dsa.FieldReverser(cls.context.memory_handler)
        cls.pta = pointertypes.PointerFieldReverser(cls.context.memory_handler)
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
        return

    def test_decodeFields(self):
        for s in self.context.listStructures():
            self.dsa.reverse_record(self.context, s)
            pointer_fields = [f for f in s.get_fields() if f.is_pointer()]
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s.get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(pointer_fields), 2)
            elif len(s) == 20:  # test3, 1 pointer on create
                # fields, no heuristic to detect medium sized int
                # TODO untyped of size < 8 == int * x
                # print s.toString()
                self.assertEqual(len(s.get_fields()), 3)  # discutable
                self.assertEqual(len(pointer_fields), 1)
        return

    def test_resolvePointers(self):
        for s in self.context.listStructures():
            self.dsa.reverse_record(self.context, s)
        for s in self.context.listStructures():
            self.pta.reverse_record(self.context, s)
        self.assertTrue(True)  # test no error

    def test_resolvePointers2(self):
        for s in self.context.listStructures():
            self.dsa.reverse_record(self.context, s)
            self.assertEqual(s.get_reverse_level(), 10)
        for s in self.context.listStructures():
            log.debug('RLEVEL: %d' % s.get_reverse_level())
            self.pta.reverse_record(self.context, s)
            pointer_fields = [f for f in s.get_fields() if f.is_pointer()]
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s.get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(pointer_fields), 2)

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
                elif name in ['_dirty', '_AnonymousRecord__address', '_AnonymousRecord__record_type']:
                    self.assertTrue(value)
                elif name in ['_fields']:
                    self.assertEqual(value, list())
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
        heap_walker = finder.list_heap_walkers()[0]
        heap_addr = heap_walker.get_heap_address()
        cls.context = context.get_context_for_address(cls.memory_handler, heap_addr)
        cls.target = cls.context.memory_handler.get_target_platform()
        cls.dsa = dsa.FieldReverser(cls.context.memory_handler)
        cls.pta = pointertypes.PointerFieldReverser(cls.context.memory_handler)
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
        return

    def test_string_overlap(self):
        for s in self.context.listStructures():
            # s.resolvePointers()
            self.dsa.reverse_record(self.context, s)
            log.debug(s.to_string())
        self.assertTrue(True)  # test no error

    def test_get_fields(self):
        _record = structure.AnonymousRecord(self.memory_handler, 0xdeadbeef, 40)
        word_size = self.target.get_word_size()

        f1 = fieldtypes.Field('f1', 0*word_size, fieldtypes.ZEROES, word_size, False)
        f2 = fieldtypes.Field('f2', 1*word_size, fieldtypes.ZEROES, word_size, False)
        fields = [f1, f2]
        _record_type = structure.RecordType('struct_test', 2*word_size, fields)
        _record.set_record_type(_record_type)
        # same fields
        self.assertEqual(f1, _record.get_fields()[0])
        self.assertEqual(f1, _record.get_field('f1'))
        # get_fields return a new list of fields
        x = _record.get_fields()
        self.assertEqual(x, _record.get_fields())
        x.pop(0)
        self.assertNotEqual(x, _record.get_fields())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("test_structure").setLevel(logging.DEBUG)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main(verbosity=2)
