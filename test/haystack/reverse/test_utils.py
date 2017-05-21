#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import unittest

import numpy

from haystack.reverse import utils
from haystack.reverse import context
from haystack import dump_loader


class TestBasicFunctions(unittest.TestCase):

    def setUp(self):
        pass

    def test_closestFloorValue(self):
        lst = numpy.asarray(range(0, 100, 10))
        self.assertEqual(utils.closestFloorValue(41, lst), (40, 4))
        self.assertEqual(utils.closestFloorValue(40, lst), (40, 4))
        with self.assertRaises(ValueError):
            utils.closestFloorValue(-1, lst)

        memory_handler = dump_loader.load('test/src/test-ctypes3.32.dump')
        finder = memory_handler.get_heap_finder()
        walker = finder.list_heap_walkers()[0]
        heap_addr = walker.get_heap_address()
        ctx = context.get_context_for_address(memory_handler, heap_addr)
        lst = ctx._structures_addresses
        # print ['0x%0.8x'%i for i in lst]


if __name__ == '__main__':
    unittest.main(verbosity=0)
