#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest

from haystack import dump_loader
from haystack.structures.win32 import winxpheapwalker
from haystack.outputters import text
from test.testfiles import zeus_1668_vmtoolsd_exe


log = logging.getLogger('testwinxpheap')



class TestWinXPHeapValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._memory_handler = dump_loader.load(zeus_1668_vmtoolsd_exe.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        cls._memory_handler.reset_mappings()
        cls._memory_handler = None
        return

    def setUp(self):
        self._heap_finder = self._memory_handler.get_heap_finder()
        self._validator = self._heap_finder.get_heap_validator()
        self.parser = text.RecursiveTextOutputter(self._memory_handler)
        return

    def tearDown(self):
        self._heap_finder = None
        self._validator = None
        self.parser = None
        return

    def test_get_freelists(self):
        """ List all free blocks """
        # test the heaps
        _heaps = self._heap_finder.get_heap_mappings()
        heap_sums = dict([(heap, list())
                          for heap in _heaps])
        child_heaps = dict()
        for heap in _heaps:
            my_heap = self._heap_finder._read_heap(heap, heap.get_marked_heap_address())
            log.debug('==== walking heap num: %0.2d @ %0.8x', my_heap.ProcessHeapsListIndex, heap.start)
            free_size_sum = 0
            for addr, size in self._validator.HEAP_get_freelists(my_heap):
                free_size_sum += size
            self.assertEquals(free_size_sum, my_heap.TotalFreeSize)
        return

    def test_get_segment_list(self):
        """ test the segment iterator """
        self.assertNotEqual(self._memory_handler, None)
        # test the heaps
        _heaps = self._heap_finder.get_heap_mappings()
        segments = []
        for heap in _heaps:
            heap_addr = heap.get_marked_heap_address()
            log.debug(
                '==== walking heap num: %0.2d @ %0.8x' %
                (self._heap_finder._read_heap(heap, heap_addr).ProcessHeapsListIndex, heap_addr))
            walker = self._heap_finder.get_heap_walker(heap)
            for i, segment in enumerate(self._validator.HEAP_get_segment_list(walker._heap)):
                s, e = segment.FirstEntry.value, segment.LastValidEntry.value
                segments.append((s, e))
                #ss = parser.parse(segment)
                #print ss
                log.debug("SEGMENT: FirstEntry:0x%x LastValidEntry:0x%x", segment.FirstEntry.value, segment.LastValidEntry.value)
                # all segments are linked to a heap
                self.assertEqual(segment.Heap.value, heap.start)
                self.assertEqual(segment.Signature, 0xffeeffee)
                # BaseAddress = heap address most of the time
                # except when the segment is a secondary allocated segment for the heap
                # in that case the BaseAddress is the segment itself
                log.debug("HEAP: 0x%x SEGMENT:0x%x BA:0x%x", heap.start, segment._orig_address_, segment.BaseAddress.value)
                self.assertTrue(segment.BaseAddress.value in [segment._orig_address_, heap.start])
            # in this heap
            # heap.LastSegmentIndex should be i
            log.debug("HEAP.LastSegmentIndex: 0x%x SEGMENT i:0x%x", walker._heap.LastSegmentIndex, i)
            self.assertEquals(walker._heap.LastSegmentIndex, i)
        segments.sort()
        self.assertEquals(segments, zeus_1668_vmtoolsd_exe.known_segments)
        return

    #def test_is_heap


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger('winxpheap').setLevel(level=logging.DEBUG)
    # logging.getLogger('testwalker').setLevel(level=logging.DEBUG)
    logging.getLogger('testwinxpheap').setLevel(level=logging.DEBUG)
    logging.getLogger('winheapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('winxpheapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('base').setLevel(level=logging.INFO)
    #logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    #logging.getLogger('filemappings').setLevel(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)