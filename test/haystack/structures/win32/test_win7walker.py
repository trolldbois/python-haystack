#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack.structures.win32 import win7heapwalker

log = logging.getLogger('testwalker')


class TestWin7HeapWalker(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # putty 1 was done under win7 32 bits ?
        cls._memory_handler = dump_loader.load('test/dumps/putty/putty.1.dump')
        cls._known_heaps = [(0x00390000, 8956), (0x00540000, 868),
                             (0x00580000, 111933), (0x005c0000, 1704080),
                             (0x01ef0000, 604), (0x02010000, 61348),
                             (0x02080000, 474949), (0x021f0000, 18762),
                             (0x03360000, 604), (0x04030000, 632),
                             (0x04110000, 1334), (0x041c0000, 644),
                             # from free stuf - erroneous
                             #( 0x0061a000, 1200),
                             ]
        return

    @classmethod
    def tearDownClass(cls):
        cls._memory_handler = None
        return

    def setUp(self):
        self._heap_finder = self._memory_handler.get_heap_finder()
        return

    def tearDown(self):
        self._heap_finder = None
        return

    def test_freelists(self):
        """ List all free blocks """

        # TODO test 0x0061a000 for overflow

        self.assertNotEqual(self._memory_handler, None)
        # test the heaps
        _heaps = self._heap_finder.get_heap_mappings()
        heap_sums = dict([(heap, list())
                          for heap in _heaps])
        child_heaps = dict()
        for heap in _heaps:
            log.debug(
                '==== walking heap num: %0.2d @ %0.8x' %
                (self._heap_finder._read_heap(heap).ProcessHeapsListIndex, heap.start))
            walker = self._heap_finder.get_heap_walker(heap)
            for x, s in walker._get_freelists():
                m = self._memory_handler.get_mapping_for_address(x)
                # Found new mmap outside of heaps mmaps
                if m not in heap_sums:
                    heap_sums[m] = []
                heap_sums[m].append((x, s))
            #self.assertEquals( free_size, walker.HEAP().TotalFreeSize)
            # save mmap hierarchy
            child_heaps[heap] = walker.get_heap_children_mmaps()

        # calcul cumulates
        for heap, children in child_heaps.items():
            # for each heap, look at all children
            freeblocks = map(lambda x: x[0], heap_sums[heap])
            free_size = sum(map(lambda x: x[1], heap_sums[heap]))
            finder = win7heapwalker.Win7HeapFinder(self._memory_handler)
            cheap = finder._read_heap(heap)
            log.debug(
                '-- heap 0x%0.8x \t free:%0.5x \texpected: %0.5x' %
                (heap.start, free_size, cheap.TotalFreeSize))
            total = free_size
            for child in children:
                freeblocks = map(lambda x: x[0], heap_sums[child])
                self.assertEquals(len(freeblocks), len(set(freeblocks)))
                # print heap_sums[child]
                free_size = sum(map(lambda x: x[1], heap_sums[child]))
                log.debug(
                    '     \_ mmap 0x%0.8x\t free:%0.5x ' %
                    (child.start, free_size))
                self.assertEquals(len(freeblocks), len(set(freeblocks)))
                total += free_size
            log.debug('     \= total: \t\t free:%0.5x ' % (total))

            maxlen = len(heap)
            cheap = finder._read_heap(heap)
            self.assertEquals(cheap.TotalFreeSize * 8, total)
            log.debug(
                'heap: 0x%0.8x free: %0.5x    \texpected: %0.5x    \tmmap len:%0.5x' %
                (heap.start, total, cheap.TotalFreeSize, maxlen))

        return

    def test_sorted_heaps(self):
        """ check if memory_mapping gives heaps sorted by index. """
        # self.skipTest('known_ok')
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)
        for i, m in enumerate(self._memory_handler.get_heaps()):
            # print '%d @%0.8x'%(finder._read_heap(m).ProcessHeapsListIndex,
            # m.start)
            self.assertEquals(finder._read_heap(m).ProcessHeapsListIndex, i + 1,
                              'ProcessHeaps should have correct indexes')
        return

    def test_is_heap(self):
        """ check if the isHeap fn perform correctly."""
        self.assertEquals(self._memory_handler.get_target_platform().get_os_name(), 'win7')
        heaps = self._memory_handler.get_heaps()
        self.assertEquals(len(heaps), 12)
        return

    def test_get_frontendheap(self):
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)
        # helper
        win7heap = finder._heap_module
        # heap = self._memory_handler.get_mapping_for_address(0x00390000)
        # for heap in self._memory_handler.get_heaps():
        for heap in [self._memory_handler.get_mapping_for_address(0x005c0000)]:
            allocs = list()
            walker = win7heapwalker.Win7HeapWalker(self._memory_handler, finder._heap_module, heap)
            heap_children = walker.get_heap_children_mmaps()
            committed, free = walker._get_frontend_chunks()
            # page 37
            # each UserBlock contain a 8 byte header ( first 4 encoded )
            #                                and then n-bytes of user data
            #
            # (in a free chunk)
            # the user data's first two bytes hold the next free chunk offset
            # UserBlocks + 8*NextOffset
            #     Its basically a forward pointer, offset.
            #
            # commited frontend chunks should have a flag at 0x5
            # previous chunk is at - 8*Chunk.SegmentOffset
            for chunk_addr, chunk_size in committed:
                self.assertGreater(
                    chunk_size,
                    0x8,
                    'too small chunk_addr == 0x%0.8x' %
                    (chunk_addr))

                m = self._memory_handler.get_mapping_for_address(chunk_addr)
                if m != heap:
                    self.assertIn(m, heap_children)

                # should be aligned
                self.assertEquals(chunk_addr & 7, 0)  # page 40
                st = m.read_struct(chunk_addr, win7heap.HEAP_ENTRY) # HEAP_ENTRY
                # st.UnusedBytes == 0x5    ?
                if st._0._1.UnusedBytes == 0x05:
                    prev_header_addr -= 8 * st._0._1._0.SegmentOffset
                    log.debug(
                        'UnusedBytes == 0x5, SegmentOffset == %d' %
                        (st._0._1._0.SegmentOffset))

                self.assertTrue(
                    st._0._1.UnusedBytes & 0x80,
                    'UnusedBytes said this is a BACKEND chunk , Flags | 2')
                # log.debug(st)

                ### THIS is not working. FIXME
                #st = m.readStruct( chunk_addr, win7heap.HEAP_ENTRY)
                # decode chunk ? SHOULD check if encoded

                #st = m.readStruct( chunk_addr, win7heap.HEAP_ENTRY)
                # st = st.decode(walker._heap) # returns sub Union struct

                # log.debug(st)
                #self.assertEquals(chunk_size, st.Size)

                allocs.append((chunk_addr, chunk_size))  # with header

            # FIXME - UNITTEST- you need to validate that NextOffset in
            # userblock gives same answer
            oracle = committed[0]  # TODO
            for chunk_addr, chunk_size in committed:
                m = self._memory_handler.get_mapping_for_address(chunk_addr)
                if m != heap:
                    self.assertIn(m, heap_children)
                # should be aligned
                self.assertEquals(chunk_addr & 7, 0)  # page 40
                st = m.read_struct(chunk_addr, win7heap.HEAP_ENTRY)
                # NextOffset in userblock gives same answer

            for addr, s in allocs:
                m = self._memory_handler.get_mapping_for_address(addr)
                if addr + s > m.end:
                    self.fail(
                        'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                        (m.start, m.end, addr, s, addr + s))
        return

    def test_get_chunks(self):
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)
        # heap = self._memory_handler.get_mapping_for_address(0x00390000)
        # for heap in self._memory_handler.get_heaps():
        for heap in [self._memory_handler.get_mapping_for_address(0x005c0000)]:
            allocs = list()
            walker = win7heapwalker.Win7HeapWalker(self._memory_handler, finder._heap_module, heap)
            allocated, free = walker._get_chunks()
            for chunk_addr, chunk_size in allocated:
                # self.assertLess(chunk_size, 0x800) # FIXME ???? sure ?
                self.assertGreater(
                    chunk_size, 0x8, 'too small chunk_addr == 0x%0.8x size: %d' %
                    (chunk_addr, chunk_size))
                allocs.append((chunk_addr, chunk_size))  # with header

            for addr, s in allocs:
                m = self._memory_handler.get_mapping_for_address(addr)
                if addr + s > m.end:
                    self.fail(
                        'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                        (m.start, m.end, addr, s, addr + s))
        return

    def _chunks_in_mapping(self, lst, walker):
        for addr, s in lst:
            m = self._memory_handler.get_mapping_for_address(addr)
            if addr + s > m.end:
                self.fail(
                    'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                    (m.start, m.end, addr, s, addr + s))
            ##self.assertEquals(mapping, m)
            # actually valid, if m is a children of mapping
            if m != walker._mapping:
                self.assertIn(m, walker.get_heap_children_mmaps())

    def assertMappingHierarchy(self, child, parent, comment=None):
        self.assertIn(m, self._heapChildren[parent], comment)

    # a free chunks size jumps into unknown mmap address space..
    @unittest.expectedFailure
    def test_totalsize(self):
        """ check if there is an adequate allocation rate as per get_user_allocations """
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)

        #
        # While all allocations over 0xFE00 blocks are handled by VirtualAlloc()/VirtualFree(),
        # all memory management that is greater than 0x800 blocks is handled by the back-end;
        # along with any memory that cannot be serviced by the front-end.

        #

        #self.skipTest('overallocation clearly not working')

        self.assertEquals(self._memory_handler.get_target_system(), 'win32')

        full = list()
        for heap in self._memory_handler.get_heaps():
            walker = win7heapwalker.Win7HeapWalker(self._memory_handler, finder._heap_module, heap)
            my_chunks = list()

            vallocs, va_free = walker._get_virtualallocations()
            self._chunks_in_mapping(vallocs, walker)
            vallocsize = sum([c[1] for c in vallocs])

            chunks, free_chunks = walker._get_chunks()
            self._chunks_in_mapping(chunks, walker)
            # Free chunks CAN be OVERFLOWING
            # self._chunks_in_mapping( free_chunks, walker)
            allocsize = sum([c[1] for c in chunks])
            freesize = sum([c[1] for c in free_chunks])

            fth_chunks, fth_free = walker._get_frontend_chunks()
            self._chunks_in_mapping(fth_chunks, walker)
            fth_allocsize = sum([c[1] for c in fth_chunks])

            free_lists = walker._get_freelists()
            # Free chunks CAN be OVERFLOWING
            #self._chunks_in_mapping( free_lists, walker)
            free_listssize = sum([c[1] for c in free_lists])

            my_chunks.extend(vallocs)
            my_chunks.extend(chunks)
            my_chunks.extend(free_chunks)
            my_chunks.extend(fth_chunks)
            my_chunks.extend(free_lists)

            myset = set(my_chunks)
            self.assertEquals(
                len(myset),
                len(my_chunks),
                'NON unique referenced chunks found.')

            full.extend(my_chunks)

        self.assertEquals(len(full), len(set(full)), 'duplicates allocs found')

        addrs = [addr for addr, s in full]
        self.assertEquals(
            len(addrs), len(
                set(addrs)), 'duplicates allocs found but different sizes')

        where = dict()
        for addr, s in full:
            m = self._memory_handler.get_mapping_for_address(addr)
            self.assertTrue(m, '0x%0.8x is not a valid address!' % (addr))
            if m not in where:
                where[m] = []
            if addr + s > m.end:
                log.debug(
                    'OVERFLOW 0x%0.8x-0x%0.8x, 0x%0.8x size: %d end: 0x%0.8x' %
                    (m.start, m.end, addr, s, addr + s))
                m2 = self._memory_handler.get_mapping_for_address(addr + s)
                self.assertTrue(
                    m2, '0x%0.8x is not a valid address 0x%0.8x + 0x%0.8x!' %
                    (addr + s, addr, s))
                if m2 not in where:
                    where[m2] = []
                where[m2].append(
                    (m2.start, s - m.end - addr))  # save second part
                s = m.end - addr  # save first part
            where[m].append((addr, s))

        # calculate allocated size
        for m, allocs in where.items():
            totalsize = sum([s for addr, s in allocs])
            log.debug(
                '@%0.8x size: %0.5x allocated: %0.5x = %0.2f %%' %
                (m.start, len(m), totalsize, 100 * totalsize / len(m)))
            allocs.sort()
            lastend = 0
            lasts = 0
            addsize = 0
            for addr, s in allocs:
                if addr < lastend:
                    # log.debug('0x%0.8x (%d) last:0x%0.8x-0x%0.8x (%d) new:0x%0.8x-0x%0.8x (%d)'%(m.start,
                    # len(m), lastend-lasts,lastend,lasts, addr, addr+s, s) )
                    addsize += s
                # keep last big chunk on the stack before moving to next one.
                else:
                    if addsize != 0:
                        #log.debug('previous fth_chunks cumulated to %d lasts:%d'%(addsize, lasts))
                        addsize = 0
                    lastend = addr + s
                    lasts = s
        # so chunks are englobing fth_chunks
        # _heap.ProcessHeapsListIndex give the order of heaps....
        return

    def test_search(self):
        """    Testing the loading of _HEAP in each memory mapping.
        Compare load_members results with known offsets. expect failures otherwise. """
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)
        # helper
        win7heap = finder._heap_module

        found = []
        for mapping in self._memory_handler:
            addr = mapping.start
            heap = mapping.read_struct(addr, win7heap.HEAP)
            if addr in map(lambda x: x[0], self._known_heaps):
                self.assertTrue(
                    heap.load_members(
                        self._memory_handler,
                        1000),
                    "We expected a valid hit at @ 0x%0.8x" %
                    (addr))
                found.append(addr, )
            else:
                try:
                    ret = heap.load_members(self._memory_handler, 1)
                    self.assertFalse(
                        ret,
                        "We didnt expected a valid hit at @%x" %
                        (addr))
                except Exception as e:
                    # should not raise an error
                    self.fail(
                        'Haystack should not raise an Exception. %s' %
                        (e))

        found.sort()
        self.assertEquals(map(lambda x: x[0], self._known_heaps), found)

        return

    def test_get_user_allocations(self):
        """ For each known _HEAP, load all user Allocation and compare the number of allocated bytes. """
        finder = win7heapwalker.Win7HeapFinder(self._memory_handler)

        for m in self._memory_handler.get_heaps():
            #
            walker = win7heapwalker.Win7HeapWalker(self._memory_handler, finder._heap_module, m)
            total = 0
            for chunk_addr, chunk_size in walker.get_user_allocations():
                self.assertTrue(chunk_addr in self._memory_handler)
                self.assertGreater(
                    chunk_size,
                    0,
                    'chunk_addr == 0x%0.8x' %
                    (chunk_addr))
                total += chunk_size

        return


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    # logging.getLogger('testwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('win7heapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    # logging.getLogger('listmodel').setLevel(level=logging.DEBUG)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    #logging.getLogger('base').setLevel(level=logging.INFO)
    #logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    #logging.getLogger('filemappings').setLevel(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
