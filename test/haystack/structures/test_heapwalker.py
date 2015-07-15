#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

# init ctypes with a controlled type size
import logging
import unittest

from haystack import dump_loader
from haystack.structures import heapwalker


class TestWalkers(unittest.TestCase):

    """Tests walkers after ctypes changes."""

    @classmethod
    def setUpClass(cls):
        cls.libc_mh_64 = dump_loader.load('test/src/test-ctypes3.64.dump')
        cls.libc_mh_32 = dump_loader.load('test/src/test-ctypes3.32.dump')
        # cls.winxp_mh_32 = dump_loader.load('test/dumps/putty/putty.1.dump')
        cls.win7_mh_32 = dump_loader.load('test/dumps/putty/putty.1.dump')

    @classmethod
    def tearDownClass(self):
        pass

    def test_make_heap_finder(self):
        libc_hf_64 = heapwalker.make_heap_finder(self.libc_mh_64)
        self.assertEqual(libc_hf_64._memory_handler.pathname, 'test/src/test-ctypes3.64.dump')
        target = libc_hf_64._memory_handler.get_target_platform()
        self.assertEqual(target.get_os_name(), 'linux')
        self.assertEqual(target.get_cpu_bits(), 64)

        libc_hf_32 = heapwalker.make_heap_finder(self.libc_mh_32)
        target = libc_hf_32._memory_handler.get_target_platform()
        self.assertEqual(target.get_os_name(), 'linux')
        self.assertEqual(target.get_cpu_bits(), 32)

        win7_hf_32 = heapwalker.make_heap_finder(self.win7_mh_32)
        target = win7_hf_32._memory_handler.get_target_platform()
        self.assertEqual(target.get_os_name(), 'win7')
        self.assertEqual(target.get_cpu_bits(), 32)

        pass

    def test_get_heap_mappings(self):
        pass

    def test__is_heap(self):
        pass

    def test_init(self):
        # test constraints applied
        # test heap module present
        pass

    def test__init_heap_type(self):
        libc_hf_64 = heapwalker.make_heap_finder(self.libc_mh_64)
        libc_64_ctypes = self.libc_mh_64.get_target_platform().get_target_ctypes()

        libc_hf_32 = heapwalker.make_heap_finder(self.libc_mh_32)
        libc_32_ctypes = self.libc_mh_32.get_target_platform().get_target_ctypes()

        # winxp_hf_32 = heapwalker.make_heap_finder(self.winxp_mh_32)
        # winxp_32_ctypes = self.winxp_mh_32.get_target_platform().get_target_ctypes()

        # winxp_hf_64 = heapwalker.make_heap_finder(self.winxp_mh_64)
        # winxp_64_ctypes = self.winxp_mh_64.get_target_platform().get_target_ctypes()

        win7_hf_32 = heapwalker.make_heap_finder(self.win7_mh_32)
        win7_32_ctypes = self.win7_mh_32.get_target_platform().get_target_ctypes()

        # win7_hf_64 = heapwalker.make_heap_finder(self.win7_mh_64)
        # win7_64_ctypes = self.win7_mh_64.get_target_platform().get_target_ctypes()

        # 32 bits
        self.assertEquals(libc_32_ctypes.sizeof(libc_hf_32._init_heap_type(), 8))
        self.assertEquals(win7_32_ctypes.sizeof(win7_hf_32._init_heap_type(), 312)) # 0x138
        #self.assertEquals(winxp_32_ctypes.sizeof(winxp_hf_32._init_heap_type(), 1430))

        # 64 bits
        self.assertEquals(libc_64_ctypes.sizeof(libc_hf_64._init_heap_type(), 16))
        # self.assertEquals(win7_64_ctypes.sizeof(win7_hf_64._init_heap_type(), 520))
        # self.assertEquals(winxp_64_ctypes.sizeof(winxp_hf_64._init_heap_type(), 2792)) #   0xae8



if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)
