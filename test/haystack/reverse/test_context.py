#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

from haystack import dump_loader
from haystack.reverse import context
from haystack.reverse import structure
from haystack.reverse import fieldtypes
from haystack.reverse import config

from test.haystack import SrcTests


log = logging.getLogger('test_memory_mapping')


class TestMappingsLinux(SrcTests):

    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load('test/dumps/ssh/ssh.1')

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None

    def test_get_context(self):
        # FIXME, move to reverser
        # print ''.join(['%s\n'%(m) for m in _memory_handler])
        with self.assertRaises(ValueError):
            context.get_context_for_address(self.memory_handler, 0x0)
        with self.assertRaises(ValueError):
            context.get_context_for_address(self.memory_handler, 0xb76e12d3)
        # [heap]
        heap_address = context.get_context_for_address(self.memory_handler, 0xb84e02d3)._heap_start
        self.assertEqual(heap_address, self.memory_handler.get_mapping_for_address(0xb84e02d3).start)


class TestMappingsWindows(SrcTests):

    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load('test/dumps/putty/putty.1.dump')
        cls.my_target = cls.memory_handler.get_target_platform()
        cls.my_ctypes = cls.my_target.get_target_ctypes()
        cls.my_utils = cls.my_target.get_target_ctypes_utils()

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        cls.my_target = None
        cls.my_ctypes = None
        cls.my_utils = None

    def test_get_context(self):
        """

        :return:
        """
        # print ''.join(['%s\n'%(m) for m in _memory_handler])
        with self.assertRaises(ValueError):
            context.get_context_for_address(self.memory_handler, 0x0)
        with self.assertRaises(ValueError):
            context.get_context_for_address(self.memory_handler, 0xb76e12d3)
        #[heap] children
        heap_address = context.get_context_for_address(self.memory_handler, 0x0062d000)._heap_start
        self.assertEqual(heap_address, self.memory_handler.get_mapping_for_address(0x005c0000).start)
        heap_address = context.get_context_for_address(self.memory_handler, 0x0063e123)._heap_start
        self.assertEqual(heap_address,self.memory_handler.get_mapping_for_address(0x005c0000).start)


class TestProcessContext(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = 'test/src/test-ctypes6.32.dump'
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(cls.dumpname)
        cls.my_target = cls.memory_handler.get_target_platform()
        cls.my_ctypes = cls.my_target.get_target_ctypes()
        cls.my_utils = cls.my_target.get_target_ctypes_utils()

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        cls.my_target = None
        cls.my_ctypes = None
        cls.my_utils = None
        config.remove_cache_folder(cls.dumpname)

    def test_save_record_type(self):
        process_context = self.memory_handler.get_reverse_context()

        _record = structure.AnonymousRecord(self.memory_handler, 0xdeadbeef, 40)
        word_size = self.my_target.get_word_size()

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

        process_context.add_reversed_type(_record_type, [1,2,3])

        r_types = list(process_context.list_reversed_types())
        self.assertEqual(r_types[0].name, 'struct_test')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.DEBUG)
    #logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)