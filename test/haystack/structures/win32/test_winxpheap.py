#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest

from haystack import dump_loader
from haystack.outputters import text
from test.testfiles import zeus_1668_vmtoolsd_exe

log = logging.getLogger('testwinxpheap')



class TestWinXPHeapValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._memory_handler = dump_loader.load(zeus_1668_vmtoolsd_exe.dumpname)
        cls._utils = cls._memory_handler.get_target_platform().get_target_ctypes_utils()
        return

    @classmethod
    def tearDownClass(cls):
        cls._utils = None
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

    @unittest.skip('freelists 0,1,2 indexes are not related to the size of the free chunks. See docs.')
    def test_get_freelists(self):
        """
        List all free blocks

         Most of the time, with FrontEndHeapType == 1 and LockVariable != 0,
            then TotalFreeSize*4 == FreeLists totals, event with LAL present.

        Except for :
        (suspicious anyways because high address)
        0x5d09d000
        0x769f7000
        0x7f6f0000
        (why this one?)
        0x3f0000

        FIXME: DOUBLE usage with test_winxpwalker.
        Need to loook at all segments ?
        # remove heap constraints verification. they have been moved to constraints.

        """
        # test the heaps
        _heaps = self._heap_finder.get_heap_mappings()
        heap_sums = dict([(heap, list())
                          for heap in _heaps])
        child_heaps = dict()
        # 0xbc5d0178,
        for heap in _heaps:
            heap_addr = heap.get_marked_heap_address()
            # 0x5d09d000
            # .FrontEndHeapType == 1 but freeslists point to nulls
            # .LockVariable is set
            # .FrontEndHeap: 0x00070688,
            #if 0x5d09d000 == heap_addr:
            #    continue
            #if 0x769f7000 == heap_addr:
            #    continue
            # FIXME - unknown situation. why free lists is null
            if 0x3f0000 == heap_addr:
                continue
            # both seems to have a interesting freelists[0] which is super blocks.
            # and frontendheap does not point to self mapping.
            # frontendheap is the LAL
            #
            my_heap = self._heap_finder._read_heap(heap, heap_addr)

            log.debug('==== walking heap num: %0.2d @ %0.8x', my_heap.ProcessHeapsListIndex, heap_addr)
            if my_heap.FrontEndHeapType == 0:
                log.info('backend heap allocator: 0x%x', heap_addr)
            elif my_heap.FrontEndHeapType == 1:
                log.info('Frontend heap allocator: 0x%x', heap_addr)

            if my_heap.LockVariable.value == 0:
                # FIXME is that bad heaps ? 0x730000 , 0x860000
                for freelist_entry in my_heap.FreeLists:
                    addr = self._utils.get_pointee_address(freelist_entry.Flink)
                    self.assertFalse(self._memory_handler.is_valid_address_value(addr))
                # in that case the freelists is going to fail/return 0
                with self.assertRaises(ValueError):
                    free_size_sum = 0
                    for addr, size in self._validator.HEAP_get_freelists(my_heap):
                        free_size_sum += size
                    #self.assertEquals(free_size_sum, my_heap.TotalFreeSize*8*2) # FIXME magic values
                    self.assertTrue(False)
            else:
                # good heaps
                for freelist_entry in my_heap.FreeLists:
                    addr = self._utils.get_pointee_address(freelist_entry.Flink)
                    self.assertTrue(self._memory_handler.is_valid_address_value(addr))
                # in that case we can check the freelists
                free_size_sum = 0
                # FIXME ## if i == 0, 1 or 2, size is not related to the index i
                for addr, size in self._validator.HEAP_get_freelists(my_heap):
                    free_size_sum += size

                if my_heap.FrontEndHeapType == 1:
                    # except 0x5d09d000
                    # 0x5d09d000.FreeLists[0] has data, but 0 size
                    # 0x5d09d000.u2 has decommitcounts (not exceptional)
                    self.assertEquals(free_size_sum, my_heap.TotalFreeSize*4)
                elif my_heap.FrontEndHeapType == 0:
                    self.assertEquals(free_size_sum, 0)
        return

    def test_get_lal(self):
        """
        List LAL free blocks
         Most of the time, with FrontEndHeapType == 1 and LockVariable != 0,
            then TotalFreeSize*4 == FreeLists totals, event with LAL present.

        """
        # test the heaps
        _heaps = self._heap_finder.get_heap_mappings()
        heap_sums = dict([(heap, list())
                          for heap in _heaps])
        child_heaps = dict()
        # 0xbc5d0178,
        for heap in _heaps:
            heap_addr = heap.get_marked_heap_address()
            # 0x5d09d000.FrontEndHeapType == 1 but freeslists point to nulls, heap points to null
            # Exception heap.0x5d09d000:"FrontEndHeap": 0x00070688,
            #if 0x5d09d000 == heap_addr:
            #    continue
            #if 0x769f7000 == heap_addr:
            #    continue
            #if 0x3f0000 != heap_addr:
            #    continue
            #if 0xb70000 != heap_addr:
            #    continue
            # both seems to have a interesting freelists[0] which is super blocks.
            # and frontendheap does not point to self mapping.
            # frontendheap is the LAL
            #
            my_heap = self._heap_finder._read_heap(heap, heap_addr)

            if False:
                log.debug('==== walking heap num: %0.2d @ %0.8x', my_heap.ProcessHeapsListIndex, heap_addr)
                if my_heap.FrontEndHeapType == 0:
                    log.debug('backend heap allocator: 0x%x', heap_addr)
                elif my_heap.FrontEndHeapType == 1:
                    log.debug('Frontend heap allocator: 0x%x', heap_addr)

            if my_heap.LockVariable.value == 0:
                # FIXME is that bad heaps ? 0x730000 , 0x860000
                for freelist_entry in my_heap.FreeLists:
                    addr = self._utils.get_pointee_address(freelist_entry.Flink)
                    self.assertFalse(self._memory_handler.is_valid_address_value(addr))
                # in that case the freelists is going to fail/return 0
                #with self.assertRaises(ValueError):
                free_size_sum = 0
                for addr, size in self._validator.HEAP_get_lookaside_chunks(my_heap):
                    free_size_sum += size
                    #self.assertEquals(free_size_sum, my_heap.TotalFreeSize*8*2) # FIXME magic values
                    #self.assertTrue(False)
            else:
                # good heaps
                for freelist_entry in my_heap.FreeLists:
                    addr = self._utils.get_pointee_address(freelist_entry.Flink)
                    self.assertTrue(self._memory_handler.is_valid_address_value(addr))
                # in that case we can check the freelists
                free_size_sum = 0
                for addr, size in self._validator.HEAP_get_lookaside_chunks(my_heap):
                    free_size_sum += size

                if my_heap.FrontEndHeapType == 1:
                    # except 0x5d09d000
                    # 0x5d09d000.FreeLists[0] has data, but 0 size
                    # 0x5d09d000.u2 has decommitcounts (not exceptional)
                    #self.assertEquals(free_size_sum, my_heap.TotalFreeSize*4)
                    pass
                elif my_heap.FrontEndHeapType == 0:
                    #self.assertEquals(free_size_sum, 0)
                    pass
                #log.debug("HEAP type: %d", my_heap.FrontEndHeapType)
                #log.debug("HEAP: 0x%x LAL free_size_sum: %x, my_heap.TotalFreeSize*4: %x", heap_addr, free_size_sum, my_heap.TotalFreeSize*4)
                # DEBUG
                fl=0
                lal_free = free_size_sum
                for addr, size in self._validator.HEAP_get_freelists(my_heap):
                    free_size_sum += size
                    fl += size
                #log.debug("HEAP: 0x%x LAL+FreeLists(0x%x): free_size_sum:0x%x, my_heap.TotalFreeSize*4:0x%x", heap_addr, fl, free_size_sum, my_heap.TotalFreeSize*4)
                if my_heap.TotalFreeSize*4 == fl:
                    log.debug("HEAP: 0x%x t:%d TFSx4 == FreeLists 0x%x LAL_free: 0x%x", heap_addr, my_heap.FrontEndHeapType, fl, lal_free)
                else:
                    log.debug("HEAP: 0x%x t:%d TFSx4 0x%x != FreeLists 0x%x LAL_free: 0x%x", heap_addr, my_heap.FrontEndHeapType, my_heap.TotalFreeSize*4, fl, lal_free)

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
                #ss = self.parser.parse(segment)
                #print ss
                log.debug("SEGMENT: FirstEntry:0x%x LastValidEntry:0x%x", segment.FirstEntry.value, segment.LastValidEntry.value)
                if segment.Heap.value == 0:
                    log.warning("HEAP 0x%x segment 0x%x heap value is NULL", heap_addr, segment._orig_address_)
                # all segments are linked to a heap
                #self.assertEqual(segment.Heap.value, heap.start)
                #self.assertEqual(segment.Signature, 0xffeeffee)
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

    def test_get_heaps(self):
        heaps = self._heap_finder.get_heap_mappings()
        self.assertEquals(len(heaps), len(zeus_1668_vmtoolsd_exe.known_heaps))

    def test_is_heaps(self):
        heaps = self._heap_finder.get_heap_mappings()
        self.assertEquals(len(heaps), len(zeus_1668_vmtoolsd_exe.known_heaps))
        for addr, size in zeus_1668_vmtoolsd_exe.known_heaps:
            heap = self._memory_handler.get_mapping_for_address(addr)
            self.assertTrue(heap.is_marked_as_heap())
            heap_addr = heap.get_marked_heap_address()
            self.assertTrue(heap_addr is not None)
            self.assertTrue(self._heap_finder._is_heap(heap, heap_addr))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('testwinxpheap').setLevel(level=logging.DEBUG)
    #logging.getLogger('winxpheap').setLevel(level=logging.DEBUG)
    #logging.getLogger('winxpheapwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('listmodel').setLevel(level=logging.DEBUG)

    # logging.getLogger('winxpheap').setLevel(level=logging.DEBUG)
    # logging.getLogger('testwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('winheapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('base').setLevel(level=logging.INFO)
    #logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    #logging.getLogger('filemappings').setLevel(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)