#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.listmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import dump_loader
from haystack import utils


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

from test.haystack import SrcTests

class TestListStruct(unittest.TestCase):

    """
    haystack --dumpname putty.1.dump --string haystack.structures.win32.win7heap.HEAP refresh 0x390000
    """

    def setUp(self):
        self.mappings = dump_loader.load('test/dumps/putty/putty.1.dump')

    def tearDown(self):
        self.mappings = None

    def test_iter(self):
        #offset = 0x390000
        from haystack.structures.win32 import win7heap
        offset = 0x1ef0000
        self.m = self.mappings.get_mapping_for_address(offset)
        self.heap = self.m.read_struct(offset, win7heap.HEAP)

        self.assertTrue(self.heap.loadMembers(self.mappings, 10))

        segments = [
            segment for segment in self.heap.iterateListField(
                self.mappings,
                'SegmentList')]
        self.assertEquals(len(segments), 1)

        ucrs = [
            ucr for ucr in segment.iterateListField(
                self.mappings,
                'UCRSegmentList') for segment in segments]
        self.assertEquals(len(ucrs), 1)

        logging.getLogger('root').debug('VIRTUAL')
        allocated = [
            block for block in self.heap.iterateListField(
                self.mappings,
                'VirtualAllocdBlocks')]
        self.assertEquals(len(allocated), 0)  # 'No vallocated blocks'

        for block in self.heap.iterateListField(
                self.mappings, 'VirtualAllocdBlocks'):
            print 'commit %x reserve %x' % (block.CommitSize, block.ReserveSize)

        return

    def test_getListFieldInfo(self):
        from haystack.structures.win32 import win7heap

        heap = win7heap.HEAP()
        self.assertEquals(
            heap._getListFieldInfo('SegmentList'), (win7heap.HEAP_SEGMENT, -16))

        seg = win7heap.HEAP_SEGMENT()
        self.assertEquals(
            seg._getListFieldInfo('UCRSegmentList'), (win7heap.HEAP_UCR_DESCRIPTOR, -8))

    def test_otherHeap(self):
        #self.skipTest('not ready')
        from haystack.structures.win32 import win7heap

        heaps = [0x390000, 0x00540000, 0x005c0000, 0x1ef0000, 0x21f0000]
        for addr in heaps:
            m = self.mappings.get_mapping_for_address(addr)
            # print '\n+ Heap @%x size: %d'%(addr, len(m))
            heap = m.read_struct(addr, win7heap.HEAP)
            self.assertTrue(heap.loadMembers(self.mappings, 10))
            segments = [
                segment for segment in heap.iterateListField(
                    self.mappings,
                    'SegmentList')]
            self.assertEquals(len(segments), 1)

            allocated = [
                block for block in heap.iterateListField(
                    self.mappings,
                    'VirtualAllocdBlocks')]
            self.assertEquals(len(allocated), 0)

class TestListStructTest6(SrcTests):
    """
    """

    def setUp(self):
        self.mappings = dump_loader.load('test/src/test-ctypes6.32.dump')
        self.memdumpname = 'test/src/test-ctypes6.32.dump'
        self._load_offsets_values(self.memdumpname)
        sys.path.append('test/src/')
        from test.src import ctypes6
        from test.src import ctypes6_gen32
        model.copyGeneratedClasses(ctypes6_gen32, ctypes6)
        model.registerModule(ctypes6)
        # apply constraints
        ctypes6.populate(self.mappings.config)
        self.offset = self.offsets['test1'][0]
        self.m = self.mappings.get_mapping_for_address(self.offset)
        self.usual = self.m.read_struct(self.offset, ctypes6.struct_usual)

    def tearDown(self):
        self.mappings = None
        self.m = None
        self.usual = None

    def test_iter(self):

        self.assertTrue(self.usual.loadMembers(self.mappings, 10))

        nodes_addrs = [
            el for el in self.usual.root._iterateList(
                self.mappings)]
        # test that we have a list of two structures in a list
        self.assertEquals(len(nodes_addrs), 2)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
