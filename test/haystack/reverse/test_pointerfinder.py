#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import unittest

from haystack.mappings.base import MemoryHandler
from haystack.reverse import pointerfinder
import test_pattern

class TestPointer(test_pattern.SignatureTests):

    def setUp(self):
        super(TestPointer, self).setUp()
        self.mmap, self.values = self._make_mmap_with_values(self.seq)
        self.name = 'test_dump_1'

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
        mmap,values = self._make_mmap(self._mstart, self._mlength, self._struct_offset,
                               intervals, self.word_size)
        self.memory_handler = MemoryHandler([mmap], self.target, 'test')
        return mmap, values


class TestPointerSearcher(TestPointer):

    def test_iter(self):
        self.pointerSearcher = pointerfinder.PointerSearcher(self.mmap)
        iters = [value for value in self.pointerSearcher]
        values = self.pointerSearcher.search()
        self.assertEqual(iters, values)
        self.assertEqual(self.values, values)
        self.assertEqual(self.values, iters)


class TestPointerEnumerator(TestPointer):

    def test_iter(self):
        self.pointerEnum = pointerfinder.PointerEnumerator(self.mmap)
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


if __name__ == '__main__':
    unittest.main()
