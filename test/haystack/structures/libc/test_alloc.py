#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import struct
import operator
import os
import unittest
import pickle
import sys


from haystack import model
from haystack import dump_loader

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger("test_alloc")


class TestAllocator(unittest.TestCase):

    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/dumps/ssh/ssh.1')

    def tearDown(self):
        from haystack import model
        self.mappings = None
        model.reset()

    def test_search(self):
        """ def search(mappings, heap, filterInuse=False ):"""
        self.skipTest('notready')
        return

    def test_chunks_numbers(self):
        """ Count all user allocations and free chunks"""
        # self.skipTest('notready')
        from haystack.structures.libc import ctypes_malloc as ctypes_alloc
        from haystack.structures.libc import libcheapwalker

        heaps = self.mappings.get_heaps()
        self.assertEquals(len(heaps), 1)

        heap = heaps[0]
        self.assertTrue(ctypes_alloc.is_malloc_heap(self.mappings, heap))

        walker = libcheapwalker.LibcHeapWalker(self.mappings, heap, 0)
        #
        allocs = walker.get_user_allocations()
        self.assertEquals(len(allocs), 2568)
        size = sum([size for addr, size in allocs])
        self.assertEquals(size, 105616)

        #
        free = walker.get_free_chunks()
        self.assertEquals(len(free), 7)
        size = sum([size for addr, size in free])
        self.assertEquals(size, 19252)

        return


class TestAllocatorSimple(unittest.TestCase):

    def setUp(self):
        model.reset()
        self.mappings = dump_loader.load('test/src/test-ctypes6.32.dump')

    @classmethod
    def tearDownClass(self):
        self.mappings = None
        model.reset()
        return

    def test_ctypes6(self):
        from haystack.structures.libc import ctypes_malloc as ctypes_alloc
        from haystack.structures.libc import libcheapwalker
        heaps = self.mappings.get_heaps()
        self.assertEquals(len(heaps), 1)

        heap = heaps[0]
        self.assertTrue(ctypes_alloc.is_malloc_heap(self.mappings, heap))

        walker = libcheapwalker.LibcHeapWalker(self.mappings, heap, 0)
        # we should have 3 structures + 1 empty chunks
        allocs = walker.get_user_allocations()
        self.assertEquals(len(allocs), 3)

        # the empty chunk
        free = walker.get_free_chunks()
        self.assertEquals(len(free), 1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    logging.getLogger('base').setLevel(level=logging.INFO)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
