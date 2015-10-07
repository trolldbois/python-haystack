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
        config.remove_cache_folder(cls.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        return

    def test_reverse_heap(self):
        log.info('START test test_reverseInstances')
        ctx = reversers.reverse_heap(self.dumpname, ssh_1_i386_linux.known_heaps[0][0])

        memory_handler = ctx.memory_handler
        finder = memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()

        self.assertEqual(len(heaps), len(ssh_1_i386_linux.known_heaps))
        #pointers
        self.assertEqual(2236, len(ctx.listPointerValueInHeap()))
        self.assertEqual(2568, len(ctx.list_allocations_addresses()))
        self.assertEqual(2568, len(ctx._get_structures()))
        self.assertEqual(2568, ctx.structuresCount())
        self.assertIn('ssh.1/cache/b84e0000.ctx', ctx.get_filename_cache_context())
        self.assertIn('ssh.1/cache/b84e0000.headers_values.py', ctx.get_filename_cache_headers())
        self.assertIn('ssh.1/cache/b84e0000.graph.gexf', ctx.get_filename_cache_graph())
        self.assertIn('ssh.1/cache/structs', ctx.get_folder_cache_structures())

        return


class TestBytes(unittest.TestCase):

    _bytes ='\xc81\x0b\x00\xa8*\x0b\x00\x01\x00\x00\x00\x00\x00\x00\x00f \x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\xe0\xa9`\x9dz3\xd0\x11\xbd\x88\x00\x00\xc0\x82\xe6\x9a\xed\x03\x00\x00\x01\x00\x00\x00\xc8\xfc\xbe\x02p\x0c\x00\x00\x08\x00\x00\x00\x1d\x00\x02\x00L\xfd\xbe\x02\xd8\x91\x1b\x01\x00\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00R\x00S\x00V\x00P\x00 \x00T\x00C\x00P\x00 \x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00 \x00P\x00r\x00o\x00v\x00i\x00d\x00e\x00r\x00\x00\x00f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xe9\x90|\xf2\x94\x80|\x00P\xfd\x7f\x00\x00\x1c\x00\x08\x00\x00\x00\x00\x00\x00\x00t\xfc\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x00\x00\xc3\x00\x00\x00\x00\x00\x88\xb0\xd2\x01\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|h^\xd0\x01\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\xc3\x00\x01\x00\x00\x000\x02\x1c\x00\x02\x00\x00\x00\x90\xb0\xd2\x01\x03\x00\x00\x00\x02\x00\x00\x00h^\xd0\x010\x02\x1c\x00\xd8>\xd4\x010\xf0\xfc\x00\xb8\x02\x1c\x00\xe8?\xd4\x01\xd8\x01\x1c\x00\x00\x00\x00\x00\x10\x00\x00\x00\xe8?\xd4\x01\x0c\x00\x00\x00\x05\x00\x00\x00\xf0\x06\x91|\xe0\x01\x1c\x00\x18\x00\x00\x00\xe0>\xd4\x01\x00\x00\x1c\x00\x01\x00\x00\x00\x08\x00\x00\x00\xe0\x01\x1c\x00@\x00\x00\x00\xf0?\xd4\x01\xa8\x04\x1c\x00\x00\x00\x1c\x00Om\x01\x01\x84^\xd0\x01`\x00\x00\x00\xb8\x02\x1c\x00\x00\x00\x00\x00\xd8>\xd4\x01\x88\xfc\xbe\x02F\x0f\x91|\r\x00\x00\x00\xd8>\xd4\x01\x00\x00\x1c\x00\x10<\xd4\x01\x00\x00\x00\x00\\\xfd\xbe\x02\\\r\x91|\x00\x00\x1c\x00\x91\x0e\x91|\x08\x06\x1c\x00m\x05\x91|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02\x00\x00\xc3\x00\x0c\x00\x00\x00\x10<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00\x00\x00\x00\x00\x18<\xd4\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x0c\x00\x00(\xfd\xbe\x02\xa8\x04\x1c\x00\xd0\x0c\x00\x00@\x00\x00\x00\x03\x00\x00\x00\x18<\xd4\x01\xa8\x04\x1c\x00`\xab\xf0\x00\xc8\x02\x00\x00\xec<\xca\x02\x0c\x00\x0e\x00<V_u\x00\x00\x00\x00\xf8\xfc\xbe\x02\xec<\xca\x02\x00\x00\x00\x00`\xab\xf0\x00P\xfd\xbe\x02l\xfb\x90|q\xfb\x90|`\xab\xf0\x00\x00\x00\x00\x00\xec<\xca\x02,\xfd\xbe\x02%SystemRoot%\\system32\\rsvpsp.dll\x00\x003\x00B\x006\x004\x00B\x007\x00}\x00\x00\x00\xbe\x02\x05\x00\x00\x00\xe6-\xfd\x7f\x96\x15\x91|\xeb\x06\x91|\xa4\xfd\xbe\x02 8\xd4\x01\x10\x00\x00\x00\t\x04\x00\x00\x00\x01\x00\x00\xdc\xfa\xbe\x02\x00\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x04\x00\x00\x00\xaf\x9f\xd4w\xdc\xfa\xbe\x02\x05\x00\x00\x00\x96\x15\x91|\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x96\x15\x91|\xeb\x06\x91|\x00\x00\x00\x00\x00\x00\x00\x00X\x00\x00\x00\xeb\x06\x91|\x01\x00\x00\x00\xa4\xfd\xbe\x02\x01\x00\x00\x00\xff\xff\xff\xff\xd8\xa2\x92w\x08\xa3\x92w\xdc\xfa\xbe\x02\xd8\xfa\xbe\x02\x02\x00\x00\x80\x9c\xfa\xbe\x02\x90\x01\x1c\x00\xb0\x01\x00\x00\xe4\xfa\xbe\x02\xff\xff\xff\xff\xe0\xfc\xbe\x02\xab\xa5\x92wh^\xd0\x01\xdc\xfa\xbe\x02\x88\x01\x1c\x00\x00\x00\xc3\x00\x01\x00\x00\x00\x96\x15\x91|\x00\x00\x00\x00'
    addr = 0xb2e38



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("ctypes_malloc").setLevel(logging.INFO)
    logging.getLogger("base").setLevel(logging.INFO)
    logging.getLogger("heapwalker").setLevel(logging.INFO)
    logging.getLogger("filemappings").setLevel(logging.INFO)
    logging.getLogger("dsa").setLevel(logging.INFO)
    logging.getLogger("dump_loader").setLevel(logging.INFO)
    unittest.main(verbosity=2)
