#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import unittest

from haystack.reverse import config
from haystack.reverse import context
from haystack.reverse import reversers
from haystack.reverse.heuristics import dsa
from test.testfiles import ssh_1_i386_linux

log = logging.getLogger("test_reversers")


class TestStructureSizes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass
        #sys.path.append('test/src/')
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
        # os.chdir()
        self.context = context.get_context('test/src/test-ctypes3.32.dump')
        self.dsa = dsa.DSASimple(self.context.memory_handler.get_target_platform())

    def tearDown(self):
        self.context.memory_handler.reset_mappings()
        self.context = None

    @unittest.skip('DEBUGging the other one')
    def test_sizes(self):
        ctypes = self.context.memory_handler.get_target_platform().get_target_ctypes()
        structs = self.context.listStructures()
        sizes = sorted(set([len(s) for s in structs]))
        ctypes3 = self.context.memory_handler.get_model().import_module('test.src.ctypes3_32')
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

    @classmethod
    def setUpClass(cls):
        cls.dumpname = 'test/dumps/ssh/ssh.1'
        cls.ctx = context.get_context(cls.dumpname, ssh_1_i386_linux.known_heaps[0][0])
        config.remove_cache_folder(cls.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        return

    def test_reverseInstances(self):
        log.info('START test test_reverseInstances')
        ctx = reversers.reverse_instances(self.dumpname)
        # FIXME test something.
        return

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("ctypes_malloc").setLevel(logging.INFO)
    logging.getLogger("base").setLevel(logging.INFO)
    logging.getLogger("heapwalker").setLevel(logging.INFO)
    logging.getLogger("filemappings").setLevel(logging.INFO)
    logging.getLogger("dsa").setLevel(logging.INFO)
    logging.getLogger("dump_loader").setLevel(logging.INFO)
    unittest.main(verbosity=2)
