#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

from haystack import dump_loader
from haystack.reverse import context
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
        self.assertEquals(
            context.get_context_for_address(self.memory_handler, 0xb84e02d3).heap,
            self.memory_handler.get_mapping_for_address(0xb84e02d3))


@unittest.skip('debug sigseg')
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
        self.putty = context.get_context('test/dumps/putty/putty.1.dump')
        memory_handler = self.putty.memory_handler
        # print ''.join(['%s\n'%(m) for m in _memory_handler])
        with self.assertRaises(ValueError):
            context.get_context_for_address(memory_handler, 0x0)
        with self.assertRaises(ValueError):
            context.get_context_for_address(memory_handler, 0xb76e12d3)
        #[heap] children
        self.assertEquals(
            context.get_context_for_address(memory_handler, 0x0062d000).heap,
            memory_handler.get_mapping_for_address(0x005c0000))
        self.assertEquals(
            context.get_context_for_address(memory_handler, 0x0063e123).heap,
            memory_handler.get_mapping_for_address(0x005c0000))
        self.putty.reset()
        self.putty = None


    def test_non_allocated_pointers_are_useless(self):
        self.putty = context.get_context('test/dumps/putty/putty.1.dump')
        memory_handler = self.putty.memory_handler
        allocated_pointers = self.putty._structures_addresses
        pointers_values = self.putty._pointers_values
        pointers_offsets = self.putty._pointers_offsets

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.DEBUG)
    #logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=0)