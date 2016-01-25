#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack.allocators.win32 import winxpheapwalker
from haystack.outputters import text
from haystack.outputters import python

from test.testfiles import zeus_1668_vmtoolsd_exe

log = logging.getLogger('testwinxpwalker')

"""
for f in `ls /home/jal/outputs/vol/zeus.vmem.1668.dump` ; do
echo $f; xxd /home/jal/outputs/vol/zeus.vmem.1668.dump/$f | head | grep -c "ffee ffee" ;
done | grep -B1 "1$"
"""
class TestWinXPHeapWalker(unittest.TestCase):

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
        self.parser = text.RecursiveTextOutputter(self._memory_handler)
        return

    def tearDown(self):
        self._heap_finder = None
        self.parser = None
        return

    def test_freelists(self):
        """ List all free blocks """

        self.assertNotEqual(self._memory_handler, None)
        # test the heaps
        walkers = self._heap_finder.list_heap_walkers()
        heap_sums = dict([(heap_walker.get_heap_mapping(), list()) for heap_walker in walkers])
        child_heaps = dict()
        for heap_walker in walkers:
            heap = heap_walker.get_heap_mapping()
            heap_addr = heap_walker.get_heap_address()
            log.debug(
                '==== walking heap num: %0.2d @ %0.8x' %
                (heap_walker.get_heap().ProcessHeapsListIndex, heap_addr))
            walker = self._heap_finder.get_heap_walker(heap)
            for x, s in walker._get_freelists():
                m = self._memory_handler.get_mapping_for_address(x)
                # Found new mmap outside of heaps mmaps
                if m not in heap_sums:
                    heap_sums[m] = []
                heap_sums[m].append((x, s))
            #self.assertEquals( free_size, walker.HEAP().TotalFreeSize)
            # save mmap hierarchy
            child_heaps[heap] = walker.list_used_mappings()

        # calcul cumulates
        for heap, children in child_heaps.items():
            # for each heap, look at all children
            freeblocks = map(lambda x: x[0], heap_sums[heap])
            free_size = sum(map(lambda x: x[1], heap_sums[heap]))
            finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
            heap_walker = finder.get_heap_walker(heap)
            cheap = heap_walker.get_heap()
            log.debug('-- heap 0x%0.8x free:%0.5x expected: %0.5x', heap_addr, free_size, cheap.TotalFreeSize)
            total = free_size
            for child in children:
                freeblocks = map(lambda x: x[0], heap_sums[child])
                self.assertEquals(len(freeblocks), len(set(freeblocks)))
                # print heap_sums[child]
                free_size = sum(map(lambda x: x[1], heap_sums[child]))
                log.debug('     \_ mmap 0x%0.8x free:%0.5x ', child.start, free_size)
                self.assertEquals(len(freeblocks), len(set(freeblocks)))
                total += free_size
            log.debug('     \= total:  free:%0.5x ', total)

            maxlen = len(heap)
            cheap = heap_walker.get_heap()
            #print self.parser.parse(cheap)
            #self.assertEquals(cheap.TotalFreeSize * 8, total)
            #log.debug(
            #    'heap: 0x%0.8x free: %0.5x    expected: %0.5x    mmap len:%0.5x',
            #    heap.start, total, cheap.TotalFreeSize, maxlen)

        return

    def test_sorted_heaps(self):
        """
        check if memory_mapping gives heaps sorted by index.
        FIXME: is HEAP.ProcessHeapsListIndex supposed to be consecutive ?
        """
        # self.skipTest('known_ok')
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
        walkers = finder.list_heap_walkers()
        #print [hex(x.start) for x in heaps]
        #print [hex(x) for x,y in zeus_1668_vmtoolsd_exe.known_heaps]
        self.assertEquals(len(walkers), len(zeus_1668_vmtoolsd_exe.known_heaps))
        last = 0
        for i, heap_walker in enumerate(walkers):
            heap_addr = heap_walker.get_heap_address()
            # this = heap_walker.get_heap().ProcessHeapsListIndex
            # log.debug('%d @%0.8x', this, heap_addr)
            this = heap_addr
            # self.assertEquals(finder._read_heap(m).ProcessHeapsListIndex, i + 1,
            self.assertGreaterEqual(this, last,'heaps are sorted by base address')
            last = this
        return

    @unittest.expectedFailure
    def test_get_frontendheap(self):
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
        # helper
        # heap = self._memory_handler.get_mapping_for_address(0x00390000)
        # Mark all heaps
        for heap in finder.list_heap_walkers():
            pass
        # do the one test
        for heap in [heap]:
            allocs = list()
            walker = finder.get_heap_walker(heap)
            winxpheap = walker._heap_module
            heap_children = walker.list_used_mappings()
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
                st = m.read_struct(chunk_addr, winxpheap.HEAP_ENTRY) # HEAP_ENTRY
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
            # FIXME
            oracle = committed[0]  # TODO
            for chunk_addr, chunk_size in committed:
                m = self._memory_handler.get_mapping_for_address(chunk_addr)
                if m != heap:
                    self.assertIn(m, heap_children)
                # should be aligned
                self.assertEquals(chunk_addr & 7, 0)  # page 40
                st = m.read_struct(chunk_addr, winxpheap.HEAP_ENTRY)
                # NextOffset in userblock gives same answer

            for addr, s in allocs:
                m = self._memory_handler.get_mapping_for_address(addr)
                if addr + s > m.end:
                    self.fail(
                        'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                        (m.start, m.end, addr, s, addr + s))
        return

    def test_get_chunks(self):
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
        addr = zeus_1668_vmtoolsd_exe.known_heaps[0][0]
        for walker in finder.list_heap_walkers():
            log.debug('Looking at chunks in 0x%x', walker.get_heap_address())
            heap = walker.get_heap_mapping()
            allocated, free = walker._get_chunks()
            # self.assertNotEquals(allocated,[])
            # self.assertNotEquals(free,[])
            for chunk_addr, chunk_size in allocated:
                # self.assertLess(chunk_size, 0x800) # FIXME ???? sure ?
                self.assertGreaterEqual(
                    chunk_size, 0x8, 'too small chunk_addr == 0x%0.8x size: %d' %
                    (chunk_addr, chunk_size))
            a_sizes = sum([x[1] for x in allocated])
            f_sizes = sum([x[1] for x in free])
            log.debug("allocated: 0x%x , free: 0x%x", a_sizes, f_sizes)
            for addr, s in allocated:
                m = self._memory_handler.get_mapping_for_address(addr)
                if addr + s > m.end:
                    self.fail(
                        'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                        (m.start, m.end, addr, s, addr + s))
        return

    def _chunks_in_mapping(self, lst, walker, mapping):
        for addr, s in lst:
            m = self._memory_handler.get_mapping_for_address(addr)
            if addr + s > m.end:
                self.fail(
                    'OVERFLOW @%0.8x-@%0.8x, @%0.8x size:%d end:@%0.8x' %
                    (m.start, m.end, addr, s, addr + s))
            ##self.assertEquals(mapping, m)
            # actually valid, if m is a children of mapping
            if m != mapping:
                self.assertIn(m, walker.list_used_mappings())

    def assertMappingHierarchy(self, child, parent, comment=None):
        self.assertIn(child, self._heapChildren[parent], comment)

    # a free chunks size jumps into unknown mmap address space..
    @unittest.expectedFailure
    def test_totalsize(self):
        """ check if there is an adequate allocation rate as per get_user_allocations """
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)

        #
        # While all allocations over 0xFE00 blocks are handled by VirtualAlloc()/VirtualFree(),
        # all memory management that is greater than 0x800 blocks is handled by the back-end;
        # along with any memory that cannot be serviced by the front-end.

        #

        #self.skipTest('overallocation clearly not working')

        self.assertEquals(self._memory_handler.get_target_platform().get_os_name(), 'winxp')

        full = list()
        for heap in finder.list_heap_walkers():
            walker = finder.get_heap_walker(heap)
            my_chunks = list()

            vallocs, va_free = walker._get_virtualallocations()
            self._chunks_in_mapping(vallocs, walker, heap)
            vallocsize = sum([c[1] for c in vallocs])

            chunks, free_chunks = walker._get_chunks()
            #print chunks, free_chunks
            self._chunks_in_mapping(chunks, walker, heap)
            # Free chunks CAN be OVERFLOWING
            # self._chunks_in_mapping( free_chunks, walker)
            allocsize = sum([c[1] for c in chunks])
            freesize = sum([c[1] for c in free_chunks])

            fth_chunks, fth_free = walker._get_frontend_chunks()
            self._chunks_in_mapping(fth_chunks, walker, heap)
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
        #addrs.sort()
        #addrs2 = list(set(addrs))
        #addrs2.sort()
        #self.assertEquals(
        #    addrs, addrs2)#, 'duplicates allocs found but different sizes')
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
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)

        found = []
        for walker in finder.list_heap_walkers():
            addr = walker.get_heap_address()
            winheap = walker._heap_module
            validator = walker.get_heap_validator()
            found.append(addr, )
            heap = walker.get_heap()
            #print hex(addr)
            if addr in map(lambda x: x[0], zeus_1668_vmtoolsd_exe.known_heaps):
                self.assertTrue(validator.load_members(heap, 50), "We expected a valid hit at @ 0x%0.8x" % addr)
            else:
                ret = validator.load_members(heap, 1)
                self.assertFalse(ret, "We didnt expected a valid hit at @%x" % addr)

        found.sort()
        #print ''
        #print [hex(x) for x,y in zeus_1668_vmtoolsd_exe.known_heaps]
        #print [hex(x) for x in found]
        self.assertEquals(map(lambda x: x[0], zeus_1668_vmtoolsd_exe.known_heaps), found)

        return

    def test_get_user_allocations(self):
        """ For each known _HEAP, load all user Allocation and compare the number of allocated bytes. """
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)

        for walker in finder.list_heap_walkers():
            #
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


class TestWinXPHeapFinder(unittest.TestCase):
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
        return

    def tearDown(self):
        self._heap_finder = None
        return

    def test_is_heap(self):
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
        for addr, size in zeus_1668_vmtoolsd_exe.known_heaps:
            m = self._memory_handler.get_mapping_for_address(addr)
            # heap = m.read_struct(addr, win7heap.HEAP)
            # FIXME self.assertTrue(self._heap_finder._is_heap(m))

    def test_print_heap_alignmask(self):
        finder = winxpheapwalker.WinXPHeapFinder(self._memory_handler)
        for addr, size in zeus_1668_vmtoolsd_exe.known_heaps:
            m = self._memory_handler.get_mapping_for_address(addr)
            walker = finder.get_heap_walker(m)
            win7heap  = walker._heap_module
            heap = m.read_struct(addr, win7heap.HEAP)
            parser = python.PythonOutputter(self._memory_handler)
            x = parser.parse(heap)
            log.info("Heap: @0x%x #:%d AlignMask: 0x%x FrontEndHeapType:%d", addr, x.ProcessHeapsListIndex, x.AlignMask, x.FrontEndHeapType)
            #tparser = python.PythonOutputter(self._memory_handler)
            #print tparser.parse(heap).toString()

            self.assertEqual(x.AlignMask, 0xfffffff8)



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.DEBUG)
    #logging.getLogger('winxpheap').setLevel(level=logging.DEBUG)
    # logging.getLogger('testwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('testwinxpwalker').setLevel(level=logging.DEBUG)
    #logging.getLogger('winheapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('winxpheapwalker').setLevel(level=logging.DEBUG)
    # logging.getLogger('win7heap').setLevel(level=logging.DEBUG)
    # logging.getLogger('listmodel').setLevel(level=logging.INFO)
    #logging.getLogger('dump_loader').setLevel(level=logging.INFO)
    # logging.getLogger('searcher').setLevel(level=logging.INFO)
    #logging.getLogger('memorybase').setLevel(level=logging.INFO)
    #logging.getLogger('utils').setLevel(level=logging.INFO)
    #logging.getLogger('basicmodel').setLevel(level=logging.INFO)
    #logging.getLogger('filemappings').setLevel(level=logging.INFO)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
