#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#
from __future__ import print_function
import haystack.reverse.enumerators
import haystack.reverse.matchers

import unittest

from haystack.mappings.base import MemoryHandler
from haystack.mappings.base import AMemoryMapping
from haystack.mappings.file import LocalMemoryMapping

from haystack import dump_loader
from haystack.reverse import searchers

from . import test_pattern

from test.testfiles import zeus_856_svchost_exe

import timeit
import logging

log = logging.getLogger('test_pointerfinder')

class TestPointer(test_pattern.SignatureTests):

    def setUp(self):
        super(TestPointer, self).setUp()
        self.mmap, self.values = self._make_mmap_with_values(self.seq)
        self.name = 'test_dump_1'
        self.feedback = searchers.NoFeedback()

    def _make_mmap_with_values(self, intervals, struct_offset=None):
        """
         Make a memory map, with a fake structure of pointer pattern inside.
        Return the pattern signature

        :param intervals:
        :param struct_offset:
        :return:
        """
        # template of a memory map metadata
        self._mstart = 0x0c00000
        self._mlength = 4096  # end at (0x0c01000)
        # could be 8, it doesn't really matter
        self.word_size = self.target.get_word_size()
        if struct_offset is not None:
            self._struct_offset = struct_offset
        else:
            self._struct_offset = self.word_size*12 # 12, or any other aligned
        mmap,values = self._make_mmap(0x0c00000, 4096, self._struct_offset,
                               intervals, self.word_size)
        # add a reference to mmap in mmap2
        ammap2 = AMemoryMapping(0xff7dc000, 0xff7dc000+0x1000, '-rwx', 0, 0, 0, 0, 'test_mmap2')
        ammap2.set_ctypes(self.target.get_target_ctypes())
        mmap2 = LocalMemoryMapping.fromBytebuffer(ammap2, mmap.get_byte_buffer())
        self._memory_handler = MemoryHandler([mmap, mmap2], self.target, 'test')
        self.mmap2 = mmap2
        return mmap, values


class TestPointerSearcher(TestPointer):

    def test_iter(self):
        matcher = haystack.reverse.matchers.PointerSearcher(self._memory_handler)
        self.pointerSearcher = searchers.WordAlignedSearcher(self.mmap, matcher, self.feedback, self.word_size)
        iters = [value for value in self.pointerSearcher]
        values = self.pointerSearcher.search()
        self.assertEqual(iters, values)
        self.assertEqual(self.values, values)
        self.assertEqual(self.values, iters)


class TestPointerEnumerator(TestPointer):

    def test_iter(self):
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        self.pointerEnum = haystack.reverse.enumerators.WordAlignedEnumerator(self.mmap, matcher, self.feedback, self.word_size)
        values = [value for offset, value in self.pointerEnum]
        offsets = [offset for offset, value in self.pointerEnum]
        values_2 = [value for offset, value in self.pointerEnum.search()]
        offsets_2 = [offset for offset, value in self.pointerEnum.search()]

        self.assertEqual(values, values_2)
        self.assertEqual(offsets, offsets_2)
        self.assertEqual(self.values, values)
        self.assertEqual(self.values, values_2)

        nsig = [self._mstart + self._struct_offset]
        nsig.extend(self.seq)
        indices = [i for i in self._accumulate(nsig)]
        self.assertEqual(indices, offsets)
        self.assertEqual(indices, offsets_2)

    def test_iter_advanced(self):
        """test that pointers to other mappings are detected"""
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        self.pointerEnum1 = haystack.reverse.enumerators.WordAlignedEnumerator(self.mmap, matcher, self.feedback, self.word_size)
        offsets1, values1 = zip(*self.pointerEnum1.search())
        self.pointerEnum2 = haystack.reverse.enumerators.WordAlignedEnumerator(self.mmap2, matcher, self.feedback, self.word_size)
        offsets2, values2 = zip(*self.pointerEnum2.search())

        self.assertEqual(values1, values2)
        self.assertEqual(len(values1), len(self.seq)+1)

class TestPointerEnumeratorReal(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        #cls._memory_handler = dump_loader.load(putty_1_win7.dumpname)
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
        return

    def tearDown(self):
        self._heap_finder = None
        return

    def _stats(self, heap_addrs):
        # get the weight per mapping
        mapdict = {}
        for m in self._memory_handler.get_mappings():
            mapdict[m.start] = 0
        for addr in heap_addrs:
            m = self._memory_handler.get_mapping_for_address(addr)
            mapdict[m.start] += 1

        res = [(v,k) for k,v, in mapdict.items()]
        res.sort()
        res.reverse()
        print('Most used mappings:')
        for cnt,s in res:
            if cnt == 0:
                continue
            m = self._memory_handler.get_mapping_for_address(s)
            print(cnt, m)

    def test_pointer_enumerators(self):
        """
        Search pointers values in one HEAP
        :return:
        """
        # prep the workers
        dumpfilename = self._memory_handler.get_name()
        word_size = self._memory_handler.get_target_platform().get_word_size()
        feedback = searchers.NoFeedback()
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        finder = self._memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        walker = walkers[0]
        heap_addr = walker.get_heap_address()
        heap = walker.get_heap_mapping()
        # create the enumerator on the whole mapping
        enumerator1 = haystack.reverse.enumerators.WordAlignedEnumerator(heap, matcher, feedback, word_size)
        # collect the pointers
        if False:
            ###
            ts1 = timeit.timeit(enumerator1.search, number=3)
            import cProfile, pstats, StringIO
            pr = cProfile.Profile()
            pr.enable()
            # ... do something ...
            heap_enum = enumerator1.search()
            pr.disable()
            s = StringIO.StringIO()
            sortby = 'cumulative'
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
            print(s.getvalue())
            ###
        else:
            heap_enum = enumerator1.search()
            ts1 = 0.0
        heap_addrs1, heap_values1 = zip(*heap_enum)
        print('WordAlignedEnumerator: %d pointers, timeit %0.2f' % (len(heap_addrs1), ts1))

        self._stats(heap_addrs1)

    def test_pointer_enumerators_allocated(self):
        """
        Search pointers values in allocated chunks from one HEAP
        :return:
        """
        # prep the workers
        word_size = self._memory_handler.get_target_platform().get_word_size()
        feedback = searchers.NoFeedback()
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        finder = self._memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        heap_walker = walkers[0]
        # create the enumerator on the allocated chunks mapping
        enumerator2 = haystack.reverse.enumerators.AllocatedWordAlignedEnumerator(heap_walker, matcher, feedback, word_size)
        # collect the pointers
        if False:
            ###
            ts2 = timeit.timeit(enumerator2.search, number=3)
            import cProfile, pstats, StringIO
            pr = cProfile.Profile()
            pr.enable()
            # ... do something ...
            heap_enum2 = enumerator2.search()
            pr.disable()
            s = StringIO.StringIO()
            sortby = 'cumulative'
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
            print(s.getvalue())
            ###
        else:
            heap_enum2 = enumerator2.search()
            ts2 = 0.0
        heap_addrs2, heap_values2 = zip(*heap_enum2)
        logging.debug('AllocatedWordAlignedEnumerator: %d pointers, timeit %0.2f', len(heap_addrs2), ts2)

        self._stats(heap_addrs2)

    def test_pointer_enumerators_all(self):
        """
        Search pointers values in all HEAP
        :return:
        """
        # prep the workers
        word_size = self._memory_handler.get_target_platform().get_word_size()
        feedback = searchers.NoFeedback()
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        finder = self._memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        all_heaps_addrs = []
        for walker in walkers:
            #if heap.start != 0x03360000:
            #    continue
            heap = walker.get_heap_mapping()
            log.debug('heap is %s', heap)
            # create the enumerator on the allocated chunks mapping
            enumerator2 = haystack.reverse.enumerators.WordAlignedEnumerator(heap, matcher, feedback, word_size)
            # collect the pointers
            heap_enum2 = enumerator2.search()
            ts2 = 0.0
            if len(heap_enum2) == 0:
                logging.debug('Heap %s has no pointers in allocated blocks', heap)
            else:
                heap_addrs2, heap_values2 = zip(*heap_enum2)
                logging.debug('WordAlignedEnumerator: %d pointers, timeit %0.2f', len(heap_addrs2), ts2)
                all_heaps_addrs.extend(heap_addrs2)
                ##
                if False:
                    print("Pointers:")
                    for k,v in heap_enum2:
                        print(hex(k), hex(v))

        self._stats(all_heaps_addrs)

    def test_pointer_enumerators_allocated_all(self):
        """
        Search pointers values in allocated chunks from all HEAP
        :return:
        """
        # prep the workers
        word_size = self._memory_handler.get_target_platform().get_word_size()
        feedback = searchers.NoFeedback()
        matcher = haystack.reverse.matchers.PointerEnumerator(self._memory_handler)
        finder = self._memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()
        all_heaps_addrs = []
        for heap_walker in walkers:
            #if heap.start != 0x03360000:
            #    continue
            heap = heap_walker.get_heap_mapping()
            log.debug('heap is %s', heap)
            # create the enumerator on the allocated chunks mapping
            enumerator2 = haystack.reverse.enumerators.AllocatedWordAlignedEnumerator(heap_walker, matcher, feedback, word_size)
            # collect the pointers
            heap_enum2 = enumerator2.search()
            ts2 = 0.0
            if len(heap_enum2) == 0:
                logging.debug('Heap %s has no pointers in allocated blocks', heap)
            else:
                heap_addrs2, heap_values2 = zip(*heap_enum2)
                logging.debug('AllocatedWordAlignedEnumerator: %d pointers, timeit %0.2f', len(heap_addrs2), ts2)
                all_heaps_addrs.extend(heap_addrs2)
                ##
                if False:
                    print("Pointers:")
                    for k,v in heap_enum2:
                        print(hex(k), hex(v))
                    print("Allocations:")
                    for addr, size in heap_walker.get_user_allocations():
                        print(hex(addr), '->', hex(addr+size), '(%x)'%size)
                    print("Free chunks:")
                    for addr, size in heap_walker.get_free_chunks():
                        print(hex(addr), '->', hex(addr+size), '(%x)'%size)

        self._stats(all_heaps_addrs)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("test_pointerfinder").setLevel(logging.DEBUG)
    unittest.main()
