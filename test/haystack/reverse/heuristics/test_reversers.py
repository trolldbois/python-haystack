#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

from __future__ import print_function
import os
import logging
import unittest
import sys

from haystack import dump_loader
from haystack import constraints
from haystack.reverse import config
from haystack.reverse import context
from haystack.reverse import api
from haystack.reverse.heuristics import dsa
from haystack.reverse.heuristics import reversers
from haystack.reverse.heuristics import signature
from haystack.reverse.heuristics import pointertypes

from test.testfiles import ssh_1_i386_linux
from test.testfiles import zeus_856_svchost_exe
from test.haystack import SrcTests
from test.src import ctypes6

log = logging.getLogger("test_reversers")


class TestKnownRecordTypeReverser(SrcTests):

    def setUp(self):
        dumpname = 'test/src/test-ctypes6.64.dump'
        self.memory_handler = dump_loader.load(dumpname)
        process_context = self.memory_handler.get_reverse_context()
        process_context.create_record_cache_folder()
        # load TU values
        self._load_offsets_values(self.memory_handler.get_name())
        ##

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.dllr = None
        #config.remove_cache_folder(cls.dumpname)

    def test_preload(self):
        sys.path.append('test/src/')

        my_model = self.memory_handler.get_model()
        ctypes6_gen64 = my_model.import_module("ctypes6_gen64")

        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read('test/src/ctypes6.constraints')

        x64_validator = ctypes6.CTypes6Validator(self.memory_handler, my_constraints, ctypes6_gen64)

        record_names = ['ctypes6_gen64.%s' % n for n in ctypes6_gen64.__all__]

        krtr = reversers.KnownRecordTypeReverser(self.memory_handler, record_names, my_constraints)
        krtr.reverse()
        ## TODO enforce better constraints, and a dynamic Contraints engine
        results = krtr.get_search_results()
        for record_name, addresses in results.items():
            print(record_name, len(addresses))
        pass


class TestDoubleLinkedReverser(SrcTests):

    def setUp(self):
        dumpname = 'test/src/test-ctypes6.64.dump'
        self.memory_handler = dump_loader.load(dumpname)
        process_context = self.memory_handler.get_reverse_context()
        process_context.create_record_cache_folder()
        # load TU values
        self._load_offsets_values(self.memory_handler.get_name())
        ##
        self.dllr = reversers.DoubleLinkedListReverser(self.memory_handler)

        log.debug('Reversing Fields')
        fr = dsa.FieldReverser(self.memory_handler)
        fr.reverse()

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.dllr = None
        #config.remove_cache_folder(cls.dumpname)

    def test_double_iter(self):
        """test node1 <-> node2 <-> ... <-> node255 """
        word_size = self.memory_handler.get_target_platform().get_word_size()
        process_context = self.memory_handler.get_reverse_context()

        start_addr = self.offsets['start_list'][0]
        mid_addr = self.offsets['mid_list'][0]
        end_addr = self.offsets['end_list'][0]

        heap_context = process_context.get_context_for_address(start_addr)
        self.assertIsNotNone(heap_context)

        start = heap_context.get_record_for_address(start_addr)
        mid = heap_context.get_record_for_address(mid_addr)
        end = heap_context.get_record_for_address(end_addr)
        # print mid.to_string()
        # reverse the list
        self.dllr.reverse()
        print(mid.to_string())
        size = len(mid)
        # there is a list for this size
        self.assertIn(size, self.dllr.lists)
        # is the offset is the same for all item in the list ?

        ## self.dllr.debug_lists()
        log.debug("start: %x size: %d", start_addr, self.sizes['start_list'])
        log.debug("end: %x size: %d", end_addr, self.sizes['end_list'])

        # the second field should be "ptr_8"
        self.assertEqual(start.get_fields()[0], start.get_field('zerroes_0'))
        self.assertEqual(start.get_fields()[1], start.get_field('ptr_8'))
        self.assertEqual(start.get_fields()[2], start.get_field('zerroes_16'))
        self.assertEqual(mid.get_fields()[0], mid.get_field('small_int_0'))
        self.assertEqual(mid.get_fields()[1], mid.get_field('ptr_8'))
        self.assertEqual(mid.get_fields()[2], mid.get_field('ptr_16'))
        self.assertEqual(end.get_fields()[0], end.get_field('small_int_0'))
        self.assertEqual(end.get_fields()[1], end.get_field('zerroes_8'))
        self.assertEqual(end.get_fields()[2], end.get_field('ptr_16'))

        # while the item is of size 32, we have padding. making 40
        members_list = [l for l in self.dllr.lists[40][8] if len(l) == 255][0]
        self.assertEqual(len(members_list), 255)
        # check head
        self.assertEqual(members_list[0], start_addr)
        self.assertEqual(members_list[-1], end_addr)
        # check that our list order is correct
        self.assertEqual(start.address, members_list[0])
        self.assertEqual(mid.address, members_list[127])
        self.assertEqual(end.address, members_list[254])

        # reverse the types for the list of items 40, at offset 8
        offset = 8
        self.dllr.rename_record_type(members_list, offset)
        # print mid.to_string()

        # now the second field should be "entry" LIST ENTRY type with 2 subfields.
        one_ptr = start.get_fields()[1]
        self.assertEqual(start.get_fields()[1], start.get_field('list'))
        self.assertEqual(one_ptr.name, 'list')
        self.assertEqual(mid.get_fields()[1], mid.get_field('list'))
        self.assertEqual(end.get_fields()[1], end.get_field('list'))

        # but also types should be the same across list members
        self.assertEqual(start.get_fields()[1], end.get_field('list'))
        self.assertEqual(start.record_type, end.record_type)
        self.assertEqual(mid.record_type, end.record_type)
        # and get_fields produce different list of the same fields
        self.assertEqual(start.get_fields(), end.get_fields())

        # get the pointer value and iterate over each item
        item_list_entry_addr = start_addr+offset
        for i in range(1, 255):
            # get the pointee record
            next_item = heap_context.get_record_for_address(item_list_entry_addr-offset)
            # still of the same size, record_type and such
            self.assertEqual(len(next_item), size)
            self.assertEqual(start.record_type, next_item.record_type)
            self.assertEqual(next_item.get_fields()[1], next_item.get_field('list'))
            # anyway, start->list has 2 members
            item_list_entry = next_item.get_field('list')
            self.assertEqual(len(item_list_entry.get_fields()), 2)
            # check the names
            self.assertEqual(item_list_entry.get_fields()[0], item_list_entry.get_field('Next'))
            self.assertEqual(item_list_entry.get_fields()[1], item_list_entry.get_field('Back'))
            # get the next list item
            next_one = item_list_entry.get_field('Next')
            item_value = item_list_entry.get_value_for_field(next_one, word_size)
            #print i, hex(item_value-offset)
            self.assertEqual(item_value-offset, members_list[i])
            item_list_entry_addr = item_value

        # we should be at last item
        self.assertEqual(item_list_entry_addr-offset, end.address)

    def test_double_iter_with_head(self):
        """// test head -> node1 <-> node2 <-> ... <-> node16"""
        word_size = self.memory_handler.get_target_platform().get_word_size()
        process_context = self.memory_handler.get_reverse_context()

        head_addr = self.offsets['head_start_list'][0]
        first_addr = self.offsets['head_first_item'][0]
        last_addr = self.offsets['head_last_item'][0]

        heap_context = process_context.get_context_for_address(head_addr)
        self.assertIsNotNone(heap_context)

        head = heap_context.get_record_for_address(head_addr)
        first = heap_context.get_record_for_address(first_addr)
        last = heap_context.get_record_for_address(last_addr)
        # print mid.to_string()
        # reverse the list
        self.dllr.reverse()
        # print first.to_string()
        # print last.to_string()
        size = len(last)
        # there is a list for this size
        self.assertIn(size, self.dllr.lists)
        # is the offset is the same for all item in the list ?

        ## self.dllr.debug_lists()
        log.debug("head: %x size: %d", head_addr, self.sizes['head_start_list'])
        log.debug("first: %x size: %d", first_addr, self.sizes['head_first_item'])
        log.debug("end: %x size: %d", last_addr, self.sizes['head_last_item'])

        # reverse the types for the list of items 40, at offset 8
        offset = 8
        # while the item is of size 32, we have padding. making 40
        # we need the list with first_addr in it
        members_list = [l for l in self.dllr.lists[40][8] if first_addr in l][0]
        self.assertEqual(len(members_list), 16)
        # check head
        self.assertEqual(members_list[0], first_addr)
        self.assertEqual(members_list[-1], last_addr)
        # the head is not in the list, because head as a different size
        self.assertNotEqual(len(head), len(first))
        self.assertNotIn(head_addr, members_list)

        # reverse
        self.dllr.rename_record_type(members_list, offset)

        # get the pointer value and iterate over each item
        item_list_entry_addr = first_addr+offset
        for i in range(1, 16):
            # get the pointee record
            next_item = heap_context.get_record_for_address(item_list_entry_addr-offset)
            # still of the same size, record_type and such
            self.assertEqual(len(next_item), size)
            self.assertEqual(first.record_type, next_item.record_type)
            self.assertEqual(next_item.get_fields()[1], next_item.get_field('list'))
            # anyway, start->list has 2 members
            item_list_entry = next_item.get_field('list')
            self.assertEqual(len(item_list_entry.get_fields()), 2)
            # check the names
            self.assertEqual(item_list_entry.get_fields()[0], item_list_entry.get_field('Next'))
            self.assertEqual(item_list_entry.get_fields()[1], item_list_entry.get_field('Back'))
            # get the next list item
            next_one = item_list_entry.get_field('Next')
            item_value = item_list_entry.get_value_for_field(next_one, word_size)
            #print i, hex(item_value-offset)
            self.assertEqual(item_value-offset, members_list[i])
            item_list_entry_addr = item_value

        # we should be at last item
        self.assertEqual(item_list_entry_addr-offset, last.address)

    def test_double_iter_loop_with_head(self):
        """// test head <-> node1 <-> node2 <-> ... <-> node16 <-> head <-> node1 <-> ...."""
        word_size = self.memory_handler.get_target_platform().get_word_size()
        process_context = self.memory_handler.get_reverse_context()

        head_addr = self.offsets['head_loop_start_list'][0]
        first_addr = self.offsets['head_loop_first_item'][0]
        last_addr = self.offsets['head_loop_last_item'][0]

        heap_context = process_context.get_context_for_address(head_addr)
        self.assertIsNotNone(heap_context)

        head = heap_context.get_record_for_address(head_addr)
        first = heap_context.get_record_for_address(first_addr)
        last = heap_context.get_record_for_address(last_addr)
        # reverse the list
        self.dllr.reverse()
        size = len(last)
        # there is a list for this size
        self.assertIn(size, self.dllr.lists)
        log.debug("head: %x size: %d", head_addr, self.sizes['head_loop_start_list'])
        log.debug("first: %x size: %d", first_addr, self.sizes['head_loop_first_item'])
        log.debug("end: %x size: %d", last_addr, self.sizes['head_loop_last_item'])

        # reverse the types for the list of items 40, at offset 8
        offset = 8
        # while the item is of size 32, we have padding. making 40
        # we need the list with first_addr in it
        members_list = [l for l in self.dllr.lists[40][8] if first_addr in l][0]
        self.assertEqual(len(members_list), 16)
        # check first
        self.assertEqual(members_list[0], first_addr)
        self.assertEqual(members_list[-1], last_addr)
        # the head is not in the list, because head as a different size
        self.assertNotEqual(len(head), len(first))
        self.assertNotIn(head_addr, members_list)
        # etc...

    def test_double_iter_loop_with_head_insertion(self):
        """// test head -> node1 <-> node2 <-> ... <-> node16 <-> node1 <-> node2 ..."""
        process_context = self.memory_handler.get_reverse_context()

        head_addr = self.offsets['loop_head_insert'][0]
        first_addr = self.offsets['loop_first_item'][0]
        last_addr = self.offsets['loop_last_item'][0]

        heap_context = process_context.get_context_for_address(head_addr)
        self.assertIsNotNone(heap_context)

        head = heap_context.get_record_for_address(head_addr)
        first = heap_context.get_record_for_address(first_addr)
        last = heap_context.get_record_for_address(last_addr)
        # reverse the list
        self.dllr.reverse()
        size = len(last)
        # there is a list for this size
        self.assertIn(size, self.dllr.lists)

        self.dllr.debug_lists()
        log.debug("head: %x size: %d", head_addr, self.sizes['loop_head_insert'])
        log.debug("first: %x size: %d", first_addr, self.sizes['loop_first_item'])
        log.debug("end: %x size: %d", last_addr, self.sizes['loop_last_item'])

        # reverse the types for the list of items 40, at offset 8
        offset = 8
        # while the item is of size 32, we have padding. making 40
        # we need the list with first_addr in it
        members_list = [l for l in self.dllr.lists[40][8] if first_addr in l][0]
        self.assertEqual(len(members_list), 16)
        # check that first is in list.
        # but first is not nessarly [0] due to full loop
        ind_first = members_list.index(first_addr)
        ind_last = members_list.index(last_addr)
        list_size = len(members_list)
        # but last is before first, for sure.
        self.assertEqual(list_size % ind_first, list_size % (ind_last+1))
        # the head is not in the list, because head as a different size
        self.assertNotEqual(len(head), len(first))
        self.assertNotIn(head_addr, members_list)
        # etc...


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
        walkers = finder.list_heap_walkers()
        self.context = context.get_context_for_address(self.memory_handler, walkers[0])
        ##
        self.dsa = dsa.FieldReverser(self.memory_handler)

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
            self.dsa.reverse_record(self.context, st)
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
        #config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(ssh_1_i386_linux.dumpname)
        return

    @classmethod
    def tearDownClass(cls):
        #config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        return

    def test_reverse_heap(self):
        log.info('START test test_reverseInstances')
        ctx = api.reverse_heap(self.memory_handler, ssh_1_i386_linux.known_heaps[0][0])

        memory_handler = self.memory_handler
        finder = memory_handler.get_heap_finder()
        walkers = finder.list_heap_walkers()

        self.assertEqual(len(walkers), len(ssh_1_i386_linux.known_heaps))
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


@unittest.skip
class TestReverseZeus(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = zeus_856_svchost_exe.dumpname
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        cls.process_context = cls.memory_handler.get_reverse_context()
        cls.process_context.create_record_cache_folder()
        ##
        cls.offset = zeus_856_svchost_exe.known_records[0][0]
        cls._context = context.get_context_for_address(cls.memory_handler, cls.offset)
        api.reverse_instances(cls.memory_handler)
        return

    @classmethod
    def tearDownClass(cls):
        #config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        cls._context = None
        return

    def _v(self, record):
        if True:
            return record.get_signature_text()
        else:
            return record.to_string()

    def test_reverse_heap(self):
        #ctx = reversers.reverse_heap(self.memory_handler, zeus_856_svchost_exe.known_heaps[0][0])

        struct_d = self._context.get_record_for_address(self.offset)
        struct_d.reset()

        sig_1 = struct_d.get_signature_text()
        # print '1.', self._v(struct_d)
        #self.assertEqual(sig_1, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')

        # decode bytes contents to find basic types.
        fr = dsa.FieldReverser(self.memory_handler)
        fr.reverse()
        sig_2 = struct_d.get_signature_text()
        # print '2.', self._v(struct_d)
        # no double linked list in here
        #self.assertEqual(sig_2, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # try to find some logical constructs.
        doublelink = reversers.DoubleLinkedListReverser(self.memory_handler)
        doublelink.reverse()
        #self.assertEqual(doublelink.found, 12)
        sig_3 = struct_d.get_signature_text()
        # print '3.', self._v(struct_d)
        #self.assertEqual(sig_3, 'P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4P4P4P4P4P4P4i4z4i4i4z8P4P4z8P4i4u16z4i4z4P4P4P4P4z64P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z8272P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z176P4u4z180u4z176')
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # identify pointer relation between allocators
        pfr = pointertypes.PointerFieldReverser(self.memory_handler)
        pfr.reverse()
        sig_4 = struct_d.get_signature_text()
        # print '4.', self._v(struct_d)
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        # aggregate field of same type in an array
        #afr = reversers.ArrayFieldsReverser(self._context)
        #afr.reverse()
        #sig_5 = struct_d.get_signature_text()
        # print '5.', self._v(struct_d)
        # print struct_d.to_string()
        #import code
        #code.interact(local=locals())

        tr = signature.TypeReverser(self.memory_handler)
        tr.reverse()
        sig_6 = struct_d.get_signature_text()
        # print '6.', self._v(struct_d)
        # print "tr._similarities", tr._similarities
        for a,b in tr._similarities:
            # print self._context.get_record_for_address(a).to_string()
            # print self._context.get_record_for_address(b).to_string()
            #import code
            #code.interact(local=locals())
            pass


@unittest.skip
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
            return record.get_signature_text()
        else:
            return record.to_string()

    def test_reversers(self):

        # order of resolution should be
        #   FieldReverser
        #   DoubleLinkedListReverser
        #   PointerFieldReverser
        #   TypeReverser

        struct_d = self._context.get_record_for_address(self.offset)
        sig_1 = struct_d.get_signature_text()
        # print '1.', self._v(struct_d)

        # try to find some logical constructs.
        doublelink = reversers.DoubleLinkedListReverser(self.memory_handler)
        doublelink.reverse()
        sig_2 = struct_d.get_signature_text()
        # print '2.', self._v(struct_d)
        # no double linked list in here
        self.assertEqual('', sig_2)

        # decode bytes contents to find basic types.
        fr = dsa.FieldReverser(self.memory_handler)
        fr.reverse()
        sig_3 = struct_d.get_signature_text()
        # print '3.', self._v(struct_d)
        #self.assertEqual(sig_3, 'P8P8P8z24i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z40i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8i8z8P8P8P8P8P8P8P8P8P8P8P8P8u40P8P8P8P8P8P8P8P8P8P8i8P8T14u2z16P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z8P8z16P8')

        # identify pointer relation between allocators
        pfr = pointertypes.PointerFieldReverser(self.memory_handler)
        pfr.reverse()
        sig_4 = struct_d.get_signature_text()
        # print '4.', self._v(struct_d)

        #logging.getLogger("reversers").setLevel(logging.DEBUG)

        # aggregate field of same type in an array
        ## FIXME very very long.
        #afr = reversers.ArrayFieldsReverser(self._context)
        #afr.reverse()
        #sig_5 = struct_d.get_signature_text()
        # print '5.', self._v(struct_d)

        tr = signature.TypeReverser(self.memory_handler)
        tr.reverse()
        sig_6 = struct_d.get_signature_text()
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


class TestGraphReverser(SrcTests):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = zeus_856_svchost_exe.dumpname
        #config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        ##
        cls.offset = zeus_856_svchost_exe.known_records[0][0]
        cls._context = context.get_context_for_address(cls.memory_handler, cls.offset)
        return

    @classmethod
    def tearDownClass(cls):
        #config.remove_cache_folder(cls.dumpname)
        cls.memory_handler = None
        cls._context = None
        return

    def _v(self, record):
        if True:
            return record.get_signature_text()
        else:
            return record.to_string()

    def test_graph(self):
        log.debug('Reversing PointerGraph')
        ptrgraph = reversers.PointerGraphReverser(self.memory_handler)
        ptrgraph.reverse()


class TestEnrichedPointerAnalyserReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        cls._context = context.get_context_for_address(cls.memory_handler, 0x90000)

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler = None
        cls._context = None

    def test_doublelink(self):
        # reverse first with dsa
        _record = self._context.get_record_for_address(0xccd00)
        _record.reset()

        revdsa = dsa.FieldReverser(self.memory_handler)
        revdsa.reverse()

        rev = reversers.DoubleLinkedListReverser(self.memory_handler)
        # interesting records
        # SIG:T4i4P4P4i4z12
        # struct_bbf78 struct_a6518 struct_cca28
        # list goes from 0xccd28, 0xccd00 to 0x98268
        #_record = self._context.get_record_for_address(0xccd28)
        _record = self._context.get_record_for_address(0xccd00)
        print(_record.to_string())
        #_record.set_reverse_level(9)
        ##
        rev.reverse_record(self._context, _record)

        print(_record.to_string())
        n1 = self._context.get_record_for_address(0x000ccae8)
        print(n1.to_string())
        tail = self._context.get_record_for_address(0x98268)
        print(tail.to_string())
        expected = [0xccd28,0xccd00,0xccae8,0xcca50,0xcca28,0xcc428,0xc6878,0xdcbc8,0xdcb40,0xcd300,0xbbf78,0xbefd8,0xbecd8,0xbc560,0xbbee0,0xbbda8,0xbbb38,0xbbae0,0xa6518,0xb5d00,0xb5cd8,0xb5cb0,0xb5b70,0xb1aa8,0xa20b8,0x9e2f8,0xa1920,0xa1838,0x98268]
        size_records = len(tail)
        # offset = 8
        offset = 8
        rev.rename_all_lists()

        self.assertEqual(rev.lists[size_records][offset][0], expected)

        # rename all lists
        for size, offset_lists in rev.lists.items():
            for offset, multiple_lists in offset_lists.items():
                for members_list in multiple_lists:
                    nb = len(members_list)
                    rt = rev.rename_record_type(members_list, offset)
                    log.debug('%d members for : %s', nb, rt.to_string())


        pass


class TestTypeReverser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        cls._context = context.get_context_for_address(cls.memory_handler, 0x90000)

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler = None
        cls._context = None

    def test_doublelink(self):
        rev = signature.TypeReverser(self.memory_handler)
        # interesting records
        # SIG:T4i4P4P4i4z12
        # struct_bbf78 struct_a6518 struct_cca28
        # list goes from 0xccd28, 0xccd00 to 0x98268
        #_record = self._context.get_record_for_address(0xccd28)
        _record = self._context.get_record_for_address(0xccd00)
        print(_record.to_string())
        _record.set_reverse_level(10)
        rev.reverse_context(self._context)
        print(_record.to_string())
        pass

    def test_otherlink(self):
        # 0xa6f40, 0xa6f70
        _record = self._context.get_record_for_address(0xccd00)
        print(_record.to_string())
        #import code
        #code.interact(local=locals())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("reversers").setLevel(logging.DEBUG)
    # logging.getLogger("signature").setLevel(logging.DEBUG)
    # logging.getLogger("test_reversers").setLevel(logging.DEBUG)
    # logging.getLogger("structure").setLevel(logging.DEBUG)
    # logging.getLogger("dsa").setLevel(logging.DEBUG)
    # logging.getLogger("winxpheap").setLevel(logging.DEBUG)
    unittest.main(verbosity=2)
