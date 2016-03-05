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
from haystack.allocators import heapwalker
from haystack.abc import interfaces

from test.testfiles import zeus_1668_vmtoolsd_exe
from test.testfiles import putty_1_win7

# FIXME move user_allocation test ssh.1 self.assertEquals(len(allocs), 2568)
# FIXME move user_allocation test putty.1 self.assertEquals(len(allocs), 1733)


class TestWalkers(unittest.TestCase):

    """Tests walkers after ctypes changes."""

    @classmethod
    def setUpClass(cls):
        cls.libc_mh_64 = dump_loader.load('test/src/test-ctypes3.64.dump')
        cls.libc_mh_32 = dump_loader.load('test/src/test-ctypes3.32.dump')
        cls.winxp_mh_32 = dump_loader.load('test/dumps/minidump/cmd.dmp')
        cls.winxp_mh_64 = dump_loader.load('test/dumps/minidump/alg.dmp')
        cls.win7_mh_32 = dump_loader.load(putty_1_win7.dumpname)
        # FIXME, its loaded as a winxp
        cls.win7_mh_64 = dump_loader.load('test/dumps/keepass.test')

    @classmethod
    def tearDownClass(cls):
        cls.libc_mh_64.reset_mappings()
        cls.libc_mh_64 = None
        cls.libc_mh_32.reset_mappings()
        cls.libc_mh_32 = None
        cls.win7_mh_32.reset_mappings()
        cls.win7_mh_32 = None
        pass

    def test_make_heap_finder(self):
        libc_hf_64 = heapwalker.make_heap_finder(self.libc_mh_64)
        self.assertIn('test/src/test-ctypes3.64.dump', libc_hf_64._memory_handler.get_name(), )
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

        winxp_hf_32 = heapwalker.make_heap_finder(self.winxp_mh_32)
        winxp_32_ctypes = self.winxp_mh_32.get_target_platform().get_target_ctypes()

        winxp_hf_64 = heapwalker.make_heap_finder(self.winxp_mh_64)
        winxp_64_ctypes = self.winxp_mh_64.get_target_platform().get_target_ctypes()

        win7_hf_32 = heapwalker.make_heap_finder(self.win7_mh_32)
        win7_32_ctypes = self.win7_mh_32.get_target_platform().get_target_ctypes()

        win7_hf_64 = heapwalker.make_heap_finder(self.win7_mh_64)
        win7_64_ctypes = self.win7_mh_64.get_target_platform().get_target_ctypes()

        # 32 bits
        self.assertEquals(libc_32_ctypes.sizeof(libc_hf_32._heap_module.malloc_chunk), 8)
        # winXP
        walker = winxp_hf_32.list_heap_walkers()[0]
        self.assertEquals(winxp_32_ctypes.sizeof(walker._heap_module.HEAP), 1416)
        # win7
        walker = win7_hf_32.list_heap_walkers()[0]
        self.assertEquals(win7_32_ctypes.sizeof(walker._heap_module.HEAP), 520)# 0x138

        # 64 bits
        self.assertEquals(libc_64_ctypes.sizeof(libc_hf_64._heap_module.malloc_chunk), 16)
        walker = win7_hf_64.list_heap_walkers()[0]
        self.assertEquals(win7_64_ctypes.sizeof(walker._heap_module.HEAP), 520)
        walker = winxp_hf_64.list_heap_walkers()[0]
        self.assertEquals(winxp_64_ctypes.sizeof(walker._heap_module.HEAP), 2792) #   0xae8


class TestHeapFinder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load('test/dumps/ssh/ssh.1')
        cls.finder = cls.memory_handler.get_heap_finder()

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        pass

    def test_get_heap_mappings(self):
        walker = self.finder.list_heap_walkers()[0]
        self.assertTrue(isinstance(walker, interfaces.IHeapWalker))
        heap_0 = walker._heap_mapping
        self.assertEquals(heap_0.start, 0xb84e0000)
        self.assertEquals(heap_0.pathname, '[heap]')

    def test_get_heaps(self):
        heaps = self.finder.list_heap_walkers()
        self.assertEquals(len(heaps), 1)

    @unittest.skip("TODO linux get_stack code")
    def test_get_stack(self):
        # FIXME or BREAKME detection was made on pathname.
        self.assertEquals(self.memory_handler.get_stack().start, 0xbff45000)
        self.assertEquals(self.memory_handler.get_stack().pathname, '[stack]')


class TestHeapFinder2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load(putty_1_win7.dumpname)
        cls.finder = cls.memory_handler.get_heap_finder()

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        pass

    def test_get_heap_mappings(self):
        m = self.memory_handler.get_mapping_for_address(0x005c0000)
        walker = self.finder.get_heap_walker(m)
        self.assertTrue(isinstance(walker, interfaces.IHeapWalker))
        heap_0 = walker.get_heap_mapping()
        self.assertEquals(heap_0.start, 0x005c0000)
        self.assertEquals(heap_0.pathname, 'None')
        buf = heap_0.read_bytes(heap_0.start, 500)
        win7heap = walker._heap_module
        x = win7heap.HEAP.from_buffer_copy(buf)
        # print win7heap.HEAP.Signature
        # print repr(buf[100:104])
        # print hex(x.Signature)
        # print _memory_handler._target_platform.ctypes.sizeof(x)

    def test_get_heaps(self):
        heaps = self.finder.list_heap_walkers()
        self.assertEquals(len(heaps), 17)

    @unittest.skip("TODO win32 get_stack code")
    def test_get_stack(self):
        # TODO win32 get_stack code
        # print ''.join(['%s\n'%(m) for m in _memory_handler])
        # print _memory_handler.get_stack() # no [stack]
        self.assertEquals(self.memory_handler.get_stack().start, 0x00400000)
        self.assertEquals(
            self.memory_handler.get_stack().pathname,
            '''C:\Program Files (x86)\PuTTY\putty.exe''')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.DEBUG)
    unittest.main(verbosity=2)
