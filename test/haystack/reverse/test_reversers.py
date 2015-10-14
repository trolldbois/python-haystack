#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import unittest
import sys
import os

from haystack.reverse import config
from haystack.reverse import context
from haystack.reverse import reversers
from haystack.reverse.heuristics import dsa
from test.testfiles import ssh_1_i386_linux
from test.testfiles import zeus_856_svchost_exe
from haystack import dump_loader

from test.haystack import SrcTests

log = logging.getLogger("test_reversers")


class TestStructureSizes(SrcTests):

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
        self.memory_handler = dump_loader.load('test/src/test-ctypes3.32.dump')
        self._load_offsets_values(self.memory_handler.get_name())
        finder = self.memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()
        self.context = context.get_context_for_address(self.memory_handler, heaps[0])
        ##
        self.dsa = dsa.DSASimple(self.context.memory_handler.get_target_platform())

    def tearDown(self):
        self.memory_handler.reset_mappings()
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
        cls.memory_handler = dump_loader.load(ssh_1_i386_linux.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        return

    def test_reverse_heap(self):
        log.info('START test test_reverseInstances')
        ctx = reversers.reverse_heap(self.memory_handler, ssh_1_i386_linux.known_heaps[0][0])

        memory_handler = self.memory_handler
        finder = memory_handler.get_heap_finder()
        heaps = finder.get_heap_mappings()

        self.assertEqual(len(heaps), len(ssh_1_i386_linux.known_heaps))
        #pointers
        self.assertEqual(2236, len(ctx.listPointerValueInHeap()))
        self.assertEqual(2568, len(ctx.list_allocations_addresses()))
        self.assertEqual(2568, len(ctx._list_records()))
        self.assertEqual(2568, ctx.get_record_count())
        self.assertIn('ssh.1/cache/b84e0000.ctx', ctx.get_filename_cache_context())
        self.assertIn('ssh.1/cache/b84e0000.headers_values.py', ctx.get_filename_cache_headers())
        self.assertIn('ssh.1/cache/b84e0000.graph.gexf', ctx.get_filename_cache_graph())
        self.assertIn('ssh.1/cache/structs', ctx.get_folder_cache_structures())

        return


class Test1(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = zeus_856_svchost_exe.dumpname
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        cls._context = None
        return

    def _v(self, record):
        if True:
            return record.get_signature(text=True)
        else:
            return record.to_string()

    def test_reverse_heap(self):
        #reversers.reverse_heap(self.memory_handler, 0x7f6f0000)
        # test that we don't have a SIGSEGV on memory_handler.__book forgetting to be
        # resetted on reset_mappings
        reversers.reverse_instances(self.memory_handler.get_name())
        pass


class TestReverseZeus(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = zeus_856_svchost_exe.dumpname
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        ##
        cls.offset = zeus_856_svchost_exe.known_records[0][0]
        cls._context = context.get_context_for_address(cls.memory_handler, cls.offset)
        reversers.reverse_instances(cls.memory_handler.get_name())
        return

    @classmethod
    def tearDownClass(cls):
        config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        cls._context = None
        return

    def _v(self, record):
        if True:
            return record.get_signature(text=True)
        else:
            return record.to_string()

    def test_reverse_heap(self):
        #ctx = reversers.reverse_heap(self.memory_handler, zeus_856_svchost_exe.known_heaps[0][0])

        struct_d = self._context.get_record_for_address(self.offset)
        struct_d.reset()

        sig_1 = struct_d.get_signature(text=True)
        # print '1.', self._v(struct_d)
        #self.assertEqual(sig_1, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')

        # decode bytes contents to find basic types.
        fr = reversers.FieldReverser(self._context)
        fr.reverse()
        sig_2 = struct_d.get_signature(text=True)
        # print '2.', self._v(struct_d)
        # no double linked list in here
        #self.assertEqual(sig_2, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # try to find some logical constructs.
        doublelink = reversers.DoubleLinkedListReverser(self._context)
        doublelink.reverse()
        #self.assertEqual(doublelink.found, 12)
        sig_3 = struct_d.get_signature(text=True)
        # print '3.', self._v(struct_d)
        #self.assertEqual(sig_3, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # identify pointer relation between structures
        pfr = reversers.PointerFieldReverser(self._context)
        pfr.reverse()
        sig_4 = struct_d.get_signature(text=True)
        # print '4.', self._v(struct_d)
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # aggregate field of same type in an array
        #afr = reversers.ArrayFieldsReverser(self._context)
        #afr.reverse()
        #sig_5 = struct_d.get_signature(text=True)
        # print '5.', self._v(struct_d)
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        tr = reversers.TypeReverser(self._context)
        tr.reverse()
        sig_6 = struct_d.get_signature(text=True)
        # print '6.', self._v(struct_d)
        # print "tr._similarities", tr._similarities
        for a,b in tr._similarities:
            # print self._context.get_record_for_address(a).to_string()
            # print self._context.get_record_for_address(b).to_string()
            #import code
            #code.interact(local=locals())
            pass



class TestReversers(SrcTests):

    def setUp(self):
        self.memory_handler = dump_loader.load('test/src/test-ctypes5.64.dump')
        self._load_offsets_values(self.memory_handler.get_name())
        sys.path.append('test/src/')

        self.offset = self.offsets['struct_d'][0]
        self.m = self.memory_handler.get_mapping_for_address(self.offset)

        self._context = context.get_context_for_address(self.memory_handler, self.offset)

        # reverse the heap
        if not os.access(config.get_record_cache_folder_name(self._context.dumpname), os.F_OK):
            os.mkdir(config.get_record_cache_folder_name(self._context.dumpname))

        log.info("[+] Cache created in %s", config.get_cache_folder_name(self._context.dumpname))

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.m = None
        self.usual = None
        sys.path.remove('test/src/')

    def _v(self, record):
        if True:
            return record.get_signature(text=True)
        else:
            return record.to_string()

    def test_reversers(self):

        # order of resolution should be
        #   FieldReverser
        #   DoubleLinkedListReverser
        #   PointerFieldReverser
        #   TypeReverser

        struct_d = self._context.get_record_for_address(self.offset)
        sig_1 = struct_d.get_signature(text=True)
        # print '1.', self._v(struct_d)

        # try to find some logical constructs.
        doublelink = reversers.DoubleLinkedListReverser(self._context)
        doublelink.reverse()
        sig_2 = struct_d.get_signature(text=True)
        # print '2.', self._v(struct_d)
        # no double linked list in here
        self.assertEqual('', sig_2)

        # decode bytes contents to find basic types.
        fr = reversers.FieldReverser(self._context)
        fr.reverse()
        sig_3 = struct_d.get_signature(text=True)
        # print '3.', self._v(struct_d)
        self.assertEqual(sig_3, 'P8P8P8z24i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8P8P8P8P8P8P8P8P8P8P8P8P8u40P8P8P8P8P8P8P8P8P8P8i8P8T14u2z16P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z16P8')

        # identify pointer relation between structures
        pfr = reversers.PointerFieldReverser(self._context)
        pfr.reverse()
        sig_4 = struct_d.get_signature(text=True)
        # print '4.', self._v(struct_d)


        logging.getLogger("reversers").setLevel(logging.DEBUG)

        # aggregate field of same type in an array
        ## FIXME very very long.
        #afr = reversers.ArrayFieldsReverser(self._context)
        #afr.reverse()
        #sig_5 = struct_d.get_signature(text=True)
        # print '5.', self._v(struct_d)


        tr = reversers.TypeReverser(self._context)
        tr.reverse()
        sig_6 = struct_d.get_signature(text=True)
        # print '6.', self._v(struct_d)
        # print "tr._similarities", tr._similarities
        for a,b in tr._similarities:
            # print self._context.get_record_for_address(a).to_string()
            # print self._context.get_record_for_address(b).to_string()
            #import code
            #code.interact(local=locals())
            pass

        #self.assertNotEqual(sig_4, sig_5)
        #self.assertEqual(sig_4, 'P8P8P8z24i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8P8P8P8P8P8P8P8P8P8P8P8P8u40P8P8P8P8P8P8P8P8P8P8i8P8T14u2z16P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z16P8')
        #self.assertEqual(sig_5, 'a24z24i8a640z8a128a96u40a80i8P8T14u2z16P8a304z16P8')
        # print 'struct_d 0x%x' % self.offset

        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())






if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.getLogger("reversers").setLevel(logging.DEBUG)
    #logging.getLogger("structure").setLevel(logging.DEBUG)
    #logging.getLogger("dsa").setLevel(logging.DEBUG)
    #logging.getLogger("winxpheap").setLevel(logging.DEBUG)
    unittest.main(verbosity=2)
