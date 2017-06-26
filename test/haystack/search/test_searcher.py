#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest

from haystack.search import api
from haystack.search import searcher
from mappings import folder


class TestApiWin32Dump(unittest.TestCase):
    """
    test if the API works for windows
    """

    memdumpname = 'test/dumps/putty/putty.1.dump'
    #modulename = "test/src/putty.py"

    def setUp(self):
        self.classname = 'haystack.allocators.win32.win7heap.HEAP'
        self.known_heaps = [(0x00390000, 8956), (0x00540000, 868),
                            (0x00580000, 111933), (0x005c0000, 1704080),
                            (0x01ef0000, 604), (0x02010000, 61348),
                            (0x02080000, 474949), (0x021f0000, 18762),
                            (0x03360000, 604), (0x04030000, 632),
                            (0x04110000, 1334), (0x041c0000, 644),
                            # from free stuf
                            (0x0061a000, 1200),
                            ]
        self.memory_handler = folder.load(self.memdumpname)

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.memdumpname = None
        self.classname = None
        self.known_heaps = None

    def test_load(self):
        # this is kinda stupid, given we are using a heapwalker to
        # find the heap, and testing the heap.

        finder = self.memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        heaps = [walker.get_heap_mapping() for walker in walkers]
        my_heap = [x for x in heaps if x.start == self.known_heaps[0][0]][0]
        heap_mapping = self.memory_handler.get_mapping_for_address(self.known_heaps[0][0])
        # we want the 32 bits heap record type on 32 bits heap mappings
        heapwalker = finder.get_heap_walker(heap_mapping)
        ## Thats a 64 bits heap heapwalker = finder.get_heap_walker(heaps[0])


        my_loader = searcher.RecordLoader(self.memory_handler)
        res = my_loader.load(heapwalker._heap_module.HEAP, self.known_heaps[0][0])
        res_p = api.output_to_python(self.memory_handler, [res])
        instance, validated = res_p[0]
        # no constraints loaded, subsegmentcode pointer went to is_valid
        self.assertFalse(validated)

        # now lets just use the win7heap constraints
        my_loader = searcher.RecordLoader(self.memory_handler, heapwalker._heap_module_constraints)
        res = my_loader.load(heapwalker._heap_module.HEAP, self.known_heaps[0][0])
        res_p = api.output_to_python(self.memory_handler, [res])
        instance, validated = res_p[0]
        # no constraints loaded, subsegmentcode pointer went to is_valid
        self.assertTrue(validated)
        self.assertIsInstance(instance, object)
        self.assertEqual(instance.Signature, 0xeeffeeff)
        self.assertEqual(instance.VirtualMemoryThreshold, 0xfe00)
        self.assertEqual(instance.FrontEndHeapType, 0)

        # try a misalign read
        res = my_loader.load(heapwalker._heap_module.HEAP, self.known_heaps[0][0] + 1)
        res_p = api.output_to_python(self.memory_handler, [res])
        instance, validated = res_p[0]
        self.assertFalse(validated)
        self.assertIsInstance(instance, object)
        self.assertNotEquals(instance.Signature, 0xeeffeeff)
        self.assertEqual(instance.Signature, 0xeeffee)  # 1 byte off
        self.assertNotEquals(instance.VirtualMemoryThreshold, 0xfe00)
        self.assertEqual(instance.VirtualMemoryThreshold, 0xff0000fe)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('searcher').setLevel(logging.DEBUG)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)