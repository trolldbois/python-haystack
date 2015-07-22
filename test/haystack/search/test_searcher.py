#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest
import haystack
from haystack import dump_loader
from haystack.search import api
from haystack.search import searcher



class TestApiWin32Dump(unittest.TestCase):
    """
    test if the API works for windows
    """

    memdumpname = 'test/dumps/putty/putty.1.dump'
    #modulename = "test/src/putty.py"

    def setUp(self):
        self.classname = 'haystack.structures.win32.win7heap.HEAP'
        self.known_heaps = [(0x00390000, 8956), (0x00540000, 868),
                            (0x00580000, 111933), (0x005c0000, 1704080),
                            (0x01ef0000, 604), (0x02010000, 61348),
                            (0x02080000, 474949), (0x021f0000, 18762),
                            (0x03360000, 604), (0x04030000, 632),
                            (0x04110000, 1334), (0x041c0000, 644),
                            # from free stuf
                            (0x0061a000, 1200),
                            ]

    def tearDown(self):
        self.memdumpname = None
        self.classname = None
        self.known_heaps = None

    def test_load(self):
        # this is kinda stupid, given we are using a heapwalker to
        # find the heap, and testing the heap.
        memory_handler = dump_loader.load(self.memdumpname)
        my_target = memory_handler.get_target_platform()
        my_ctypes = my_target.get_target_ctypes()
        my_utils = my_target.get_target_ctypes_utils()
        my_model = memory_handler.get_model()
        finder = memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()
        my_heap = [ x for x in heaps if x.start == self.known_heaps[0][0]][0]
        heapwalker = memory_handler.get_heap_walker(heaps[0])
        win7heap = heapwalker._heap

        my_loader = searcher.RecordLoader(memory_handler)
        res = my_loader.load(heapwalker._heap_module.HEAP, self.known_heaps[0][0])
        res_p = haystack.output_to_python(memory_handler, [res])
        instance, validated = res_p[0]

        self.assertTrue(validated)
        self.assertIsInstance(instance, object)
        self.assertEquals(instance.Signature, 0xeeffeeff)
        self.assertEquals(instance.VirtualMemoryThreshold, 0xfe00)
        self.assertEquals(instance.FrontEndHeapType, 0)

        # try a misalign read
        res = my_loader.load(heapwalker._heap_module.HEAP, self.known_heaps[0][0] + 1)
        res_p = haystack.output_to_python(memory_handler, [res])
        instance, validated = res_p[0]
        self.assertFalse(validated)
        self.assertIsInstance(instance, object)
        self.assertNotEquals(instance.Signature, 0xeeffeeff)
        self.assertEquals(instance.Signature, 0xeeffee)  # 1 byte off
        self.assertNotEquals(instance.VirtualMemoryThreshold, 0xfe00)
        self.assertEquals(instance.VirtualMemoryThreshold, 0xff0000fe)

        return



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('searcher').setLevel(logging.DEBUG)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)