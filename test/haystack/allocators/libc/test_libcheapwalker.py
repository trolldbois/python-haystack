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

    def test_list_heap_walkers(self):
        memory_handler = dump_loader.load('test/src/test-ctypes1.64.dump')
        heap_finder = memory_handler.get_heap_finder()
        walkers = heap_finder.list_heap_walkers()
        self.assertEqual(len(walkers), 1)
        self.assertEqual(walkers[0].get_heap_mapping().pathname, '[heap]')
        memory_handler.reset_mappings()

        memory_handler = dump_loader.load('test/src/test-ctypes3.64.dump')
        heap_finder = memory_handler.get_heap_finder()
        walkers = heap_finder.list_heap_walkers()
        self.assertEqual(len(walkers), 1)
        self.assertEqual(walkers[0].get_heap_mapping().pathname, '[heap]')
        memory_handler.reset_mappings()

        memory_handler = dump_loader.load('test/src/test-ctypes3.32.dump')
        heap_finder = memory_handler.get_heap_finder()
        walkers = heap_finder.list_heap_walkers()
        self.assertEqual(len(walkers), 1)
        self.assertEqual(walkers[0].get_heap_mapping().pathname, '[heap]')
        memory_handler.reset_mappings()


class TestLibcHeapWalker(unittest.TestCase):

    def setUp(self):
        self.memory_handler = dump_loader.load('test/src/test-ctypes6.64.dump')
        self.heap_finder = self.memory_handler.get_heap_finder()
        self.walkers = self.heap_finder.list_heap_walkers()
        self.walker = self.walkers[0]

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.heap_finder = None
        self.walkers = None

    def test_get_heap_walker(self):
        self.assertIn('malloc_chunk', self.walker._heap_module.__dict__.keys())

    def test_get_user_allocations(self):
        # we should have 3 allocators + 1 empty chunks
        allocs = self.walker.get_user_allocations()
        self.assertEquals(len(allocs), 35 + 255 + 16 + 16 + 16 + 3 )

    def test_get_free_chunks(self):
        # the empty chunk
        free = self.walker.get_free_chunks()
        self.assertEquals(len(free), 1)


class TestLibcHeapWalkerBigger(unittest.TestCase):
    """ Test the libc heap walker on a bigger test case,
    a ssh process dump.
    """

    def test_chunks_numbers(self):
        """ Count all user allocations and free chunks (10 sec)"""
        memory_handler = dump_loader.load('test/dumps/ssh/ssh.1')
        heap_finder = memory_handler.get_heap_finder()
        #
        walkers = heap_finder.list_heap_walkers()
        self.assertEquals(len(walkers), 1)
        heap = walkers[0].get_heap_mapping()
        walker = heap_finder.get_heap_walker(heap)
        # test the number of allocations
        allocs = walker.get_user_allocations()
        self.assertEquals(len(allocs), 2568)
        # test the size of allocations
        size = sum([size for addr, size in allocs])
        self.assertEquals(size, 105616)
        # test the number of free chunks
        free = walker.get_free_chunks()
        self.assertEquals(len(free), 7)
        # test the size of free chunks
        size = sum([size for addr, size in free])
        self.assertEquals(size, 19252)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    # logging.getLogger('base').setLevel(level=logging.INFO)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
