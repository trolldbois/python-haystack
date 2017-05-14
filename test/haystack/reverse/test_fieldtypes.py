#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

from __future__ import print_function
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
        heap_walker = finder.list_heap_walkers()[0]
        heap_addr = heap_walker.get_heap_address()

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

    def test_zeroes(self):
        z1 = fieldtypes.ZeroField('one', 0, 1)
        self.assertEqual(len(z1), 1)
        self.assertIn('ctypes.c_ubyte*1 )', z1.to_string('\x00\x00\x00\x00'))

        z2 = fieldtypes.ZeroField('two', 0, 2)
        self.assertEqual(len(z2), 2)
        self.assertIn('ctypes.c_ubyte*2 )', z2.to_string('\x00\x00\x00\x00'))

    def test_gaps(self):
        g1 = fieldtypes.Field('gap_0', 0, fieldtypes.UNKNOWN, 1, False)
        self.assertEqual(len(g1), 1)
        self.assertTrue(g1.is_gap())
        print(g1.to_string('\x00\x00\x00\x00'))
        self.assertIn('ctypes.c_ubyte*1 )', g1.to_string('\x00\x00\x00\x00'))

        g2 = fieldtypes.Field('gap_0', 0, fieldtypes.UNKNOWN, 2, False)
        self.assertEqual(len(g2), 2)
        self.assertIn('ctypes.c_ubyte*2 )', g2.to_string('\x00\x00\x00\x00'))

    def test_is_types(self):
        # def __init__(self, astruct, offset, typename, size, isPadding):
        ptr = fieldtypes.PointerField('ptr_0', 8, 4)
        self.assertFalse(ptr.is_string())
        self.assertTrue(ptr.is_pointer())
        self.assertFalse(ptr.is_zeroes())
        self.assertFalse(ptr.is_array())
        self.assertFalse(ptr.is_integer())

    def test_equals(self):
        start = self.offsets['start_list'][0]
        _record = structure.AnonymousRecord(self.memory_handler, start, 40)
        word_size = self._target.get_word_size()

        f1 = fieldtypes.Field('f1', 0*word_size, fieldtypes.ZEROES, word_size, False)
        f2 = fieldtypes.Field('f2', 1*word_size, fieldtypes.ZEROES, word_size, False)
        fields = [f1, f2]
        _record_type = structure.RecordType('struct_text', 2*word_size, fields)
        _record.set_record_type(_record_type)

        self.assertEqual(f1, _record.get_fields()[0])
        self.assertEqual(f1, _record.get_field('f1'))

    def test_subtype(self):
        start = self.offsets['start_list'][0]
        _record = structure.AnonymousRecord(self.memory_handler, start, 40)
        word_size = self._target.get_word_size()

        f1 = fieldtypes.Field('f1', 0*word_size, fieldtypes.ZEROES, word_size, False)
        f4 = fieldtypes.Field('f2', 3*word_size, fieldtypes.ZEROES, word_size, False)
        # offset in the substruct
        fs2 = fieldtypes.PointerField('Back', 0, word_size)
        fs2.value = start
        fs3 = fieldtypes.PointerField('Next', 1*word_size, word_size)
        fs3.value = start
        # the new field sub record
        new_field = fieldtypes.RecordField(_record, 1*word_size, 'list', 'LIST_ENTRY', [fs2, fs3])
        # fieldtypes.FieldType.makeStructField(_record, 1*word_size, 'LIST_ENTRY', [fs2, fs3], 'list')
        # add them
        fields = [f1, new_field, f4]
        #_record.add_fields(fields)
        _record_type = structure.RecordType('struct_text', 40, fields)
        _record.set_record_type(_record_type)
        self.assertEqual(len(_record), 40)
        f1, f2, f3 = _record.get_fields()
        self.assertEqual(len(f1), word_size)
        self.assertEqual(len(f2), word_size*2)
        self.assertEqual(len(f3), word_size)

        self.assertEqual(f2.name, 'list')
        self.assertIsInstance(f2.field_type, fieldtypes.FieldTypeStruct)
        self.assertEqual(f2.field_type.name, 'LIST_ENTRY')

        print(_record.to_string())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
    # logging.getLogger("reversers").setLevel(level=logging.DEBUG)
    # logging.getLogger("structure").setLevel(level=logging.DEBUG)
    # logging.getLogger("field").setLevel(level=logging.DEBUG)
    # logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
