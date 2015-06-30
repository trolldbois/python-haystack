#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import os
import sys
import unittest

from haystack import config

from haystack import model, constraints
from haystack.reverse import context
from haystack.reverse import reversers
from haystack.reverse.heuristics import dsa

#import ctypes

log=logging.getLogger("test_reversers")


class TestStructureSizes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sys.path.append('test/src/')
        #import ctypes3
        #
        #node = ctypes3.struct_Node
        #node._expectedValues_ = dict(
        #    [('val1', [0xdeadbeef]), ('ptr2', [constraints.NotNull])])
        #test3 = ctypes3.struct_test3
        #test3._expectedValues_ = dict([
        #    ('val1', [0xdeadbeef]),
        #    ('val1b', [0xdeadbeef]),
        #    ('val2', [0x10101010]),
        #    ('val2b', [0x10101010]),
        #    ('me', [constraints.NotNull])])

    def setUp(self):
        model.reset()
        # os.chdir()
        self.context = context.get_context('test/src/test-ctypes3.32.dump')
        self.dsa = dsa.DSASimple(self.context.config)

    def tearDown(self):
        self.context = None
        model.reset()

    @unittest.skip('DEBUGging the other one')
    def test_sizes(self):
        ctypes = self.context.config.ctypes
        structs = self.context.listStructures()
        sizes = sorted(set([len(s) for s in structs]))
        import ctypes3
        for st in structs:  # [1:2]:
            self.dsa.analyze_fields(st)
            #print st.toString()
            # print repr(self.context.heap.readBytes(st._vaddr, len(st)))

        # there are only two struct types
        # the free chunks is not listed
        self.assertEqual(len(sizes), 2)
        self.assertEqual(len(structs), 6)

        # our compiler put a padding at the end of struct_Node
        # struct_node should be 8, no padding, but its 12.
        self.assertEqual(sizes, [12,20])
        
        #st = ctypes3.Node()
        # print st.toString(), st._expectedValues_

        self.assertEqual(ctypes.sizeof(ctypes.c_void_p),4)
        self.assertEqual(ctypes3.struct_test3.me.size,4)
        self.assertEqual(sizes[1], ctypes.sizeof(ctypes3.struct_test3))

        # our compiler put a padding at the end of struct_Node
        # struct_node should be 8, no padding, but its 12.
        self.assertNotEqual(
            sizes[0],
            ctypes.sizeof(
                ctypes3.struct_Node),
            'There should be a 4 bytes padding here')
        self.assertEqual(
            sizes[0] - 4,
            ctypes.sizeof(
                ctypes3.struct_Node),
            'There should be a 4 bytes padding here')


class TestFullReverse(unittest.TestCase):

    def setUp(self):
        model.reset()

    def tearDown(self):
        model.reset()

    def test_reverseInstances(self):
        log.info('START test test_reverseInstances')
        ctx = context.get_context('test/dumps/ssh/ssh.1')
        dumpname = 'test/dumps/ssh/ssh.1'
        ctx = ctx.config.cleanCache(dumpname)
        ctx = reversers.reverseInstances(dumpname)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("ctypes_malloc").setLevel(logging.INFO)
    logging.getLogger("base").setLevel(logging.INFO)
    logging.getLogger("heapwalker").setLevel(logging.INFO)
    logging.getLogger("filemappings").setLevel(logging.INFO)
    logging.getLogger("dsa").setLevel(logging.INFO)
    logging.getLogger("dump_loader").setLevel(logging.INFO)
    unittest.main()
