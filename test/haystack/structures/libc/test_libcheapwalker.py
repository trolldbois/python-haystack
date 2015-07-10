#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

from haystack import dump_loader

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger("test_libcheapwalker")


class TestLibcHeapFinder(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_heap_mappings(self):
        memory_handler = dump_loader.load('test/src/test-ctypes1.64.dump')
        heap_finder = memory_handler.get_heap_finder()
        mappings = heap_finder.get_heap_mappings()
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].pathname, '[heap]')

        memory_handler = dump_loader.load('test/src/test-ctypes3.64.dump')
        heap_finder = memory_handler.get_heap_finder()
        mappings = heap_finder.get_heap_mappings()
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].pathname, '[heap]')

        memory_handler = dump_loader.load('test/src/test-ctypes3.32.dump')
        heap_finder = memory_handler.get_heap_finder()
        mappings = heap_finder.get_heap_mappings()
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].pathname, '[heap]')

    def test_get_heap_walker(self):

        memory_handler = dump_loader.load('test/src/test-ctypes6.64.dump')
        heap_finder = memory_handler.get_heap_finder()
        mappings = heap_finder.get_heap_mappings()
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].pathname, '[heap]')
        walker = heap_finder.get_heap_walker(mappings[0])
        # we should have 3 structures + 1 empty chunks
        allocs = walker.get_user_allocations()
        self.assertEquals(len(allocs), 3)
        # the empty chunk
        free = walker.get_free_chunks()
        self.assertEquals(len(free), 1)


class TestAllocator(unittest.TestCase):

    def setUp(self):
        self.mappings = dump_loader.load('test/dumps/ssh/ssh.1')

    def tearDown(self):
        from haystack import model
        self.mappings = None
        model.reset()

    def test_search(self):
        """ def search(_memory_handler, heap, filterInuse=False ):"""
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


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    # logging.getLogger('base').setLevel(level=logging.INFO)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
