#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

from haystack.reverse import context
from haystack.reverse import config
from haystack.reverse.heuristics import dsa
from haystack.reverse import fieldtypes
from haystack.reverse import structure
from haystack import dump_loader

from test.haystack import SrcTests

log = logging.getLogger('test_fieldtypes')


class TestField(SrcTests):

    @classmethod
    def setUpClass(cls):
        #self.context3 = context.get_context('test/src/test-ctypes3.dump')
        cls.dumpname = 'test/src/test-ctypes6.32.dump'
        config.remove_cache_folder(cls.dumpname)

        cls.memory_handler = dump_loader.load(cls.dumpname)
        cls._target = cls.memory_handler.get_target_platform()
        finder = cls.memory_handler.get_heap_finder()
        heap = finder.get_heap_mappings()[0]
        heap_addr = heap.get_marked_heap_address()

        cls._load_offsets_values(cls.memory_handler.get_name())

        cls.context6 = context.get_context_for_address(cls.memory_handler, heap_addr)
        cls.dsa = dsa.FieldReverser(cls.context6.memory_handler)
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
        ptr = fieldtypes.PointerField(self.st, 8, fieldtypes.POINTER, 4, False)
        self.assertFalse(ptr.is_string())
        self.assertTrue(ptr.is_pointer())
        self.assertFalse(ptr.is_zeroes())
        self.assertFalse(ptr.is_array())
        self.assertFalse(ptr.is_integer())

    def test_subtype(self):
        start = self.offsets['start_list'][0]
        _record = structure.AnonymousRecord(self.memory_handler, start, 40)
        word_size = self._target.get_word_size()

        f1 = fieldtypes.Field(structure, 0*word_size, fieldtypes.ZEROES, word_size, False)
        f4 = fieldtypes.Field(structure, 3*word_size, fieldtypes.ZEROES, word_size, False)
        # offset in the substruct
        fs2 = fieldtypes.PointerField(_record, 0, fieldtypes.POINTER, word_size, False)
        fs2.value = start
        fs3 = fieldtypes.PointerField(_record, 1*word_size, fieldtypes.POINTER, word_size, False)
        fs3.value = start
        # the new field sub record
        new_field = fieldtypes.RecordField(_record, 1*word_size, 'list', 'LIST_ENTRY', [fs2, fs3])
        # fieldtypes.FieldType.makeStructField(_record, 1*word_size, 'LIST_ENTRY', [fs2, fs3], 'list')
        # add them
        fields = [f1, new_field, f4]
        _record.add_fields(fields)
        self.assertEqual(len(_record), 40)
        f1, f2, f3 = _record.get_fields()
        self.assertEqual(len(f1), word_size)
        self.assertEqual(len(f2), word_size*2)
        self.assertEqual(len(f3), word_size)

        self.assertEqual(f2.name, 'list')
        self.assertIsInstance(f2.typename, fieldtypes.FieldTypeStruct)
        self.assertEqual(f2.typename.basename, 'LIST_ENTRY')

        print _record.to_string()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
    logging.getLogger("structure").setLevel(level=logging.DEBUG)
    logging.getLogger("field").setLevel(level=logging.DEBUG)
    logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
