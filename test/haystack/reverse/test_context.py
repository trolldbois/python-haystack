#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging

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
            self.memory_handler.get_context(0x0)
        with self.assertRaises(ValueError):
            self.memory_handler.get_context(0xb76e12d3)
        # [heap]
        self.assertEquals(
            self.memory_handler.get_context(0xb84e02d3).heap,
            self.memory_handler.get_mapping_for_address(0xb84e02d3))


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
            memory_handler.get_context(0x0)
        with self.assertRaises(ValueError):
            memory_handler.get_context(0xb76e12d3)
        #[heap] children
        self.assertEquals(
            memory_handler.get_context(0x0062d000).heap,
            memory_handler.get_mapping_for_address(0x005c0000))
        self.assertEquals(
            memory_handler.get_context(0x0063e123).heap,
            memory_handler.get_mapping_for_address(0x005c0000))
        self.putty.reset()
        self.putty = None
