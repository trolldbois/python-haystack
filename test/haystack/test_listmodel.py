#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.listmodel ."""

import logging
import sys
import unittest

from haystack import constraints
from mappings import folder
from test.haystack import SrcTests
from test.src import ctypes6


class TestListStructTest6(SrcTests):
    """
    """

    def setUp(self):
        self.memory_handler = folder.load('test/src/test-ctypes6.32.dump')
        self.memdumpname = 'test/src/test-ctypes6.32.dump'
        self._load_offsets_values(self.memdumpname)
        sys.path.append('test/src/')

        my_model = self.memory_handler.get_model()
        self.ctypes6_gen32 = my_model.import_module("ctypes6_gen32")

        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read('test/src/ctypes6.constraints')

        self.x32_validator = ctypes6.CTypes6Validator(self.memory_handler, my_constraints, self.ctypes6_gen32)
        self.offset = self.offsets['test1'][0]
        self.m = self.memory_handler.get_mapping_for_address(self.offset)
        self.usual = self.m.read_struct(self.offset, self.ctypes6_gen32.struct_usual)
        # complex
        self.o_rootA = self.offsets['rootA'][0]
        self.rootA = self.m.read_struct(self.o_rootA, self.ctypes6_gen32.struct_Node)
        self.o_rootB = self.offsets['rootB'][0]
        self.rootB = self.m.read_struct(self.o_rootB, self.ctypes6_gen32.struct_Node)
        self.o_rootC = self.offsets['rootC'][0]
        self.rootC = self.m.read_struct(self.o_rootC, self.ctypes6_gen32.struct_Node)

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None
        self.m = None
        self.usual = None
        self.ctypes6_gen32 = None
        sys.path.remove('test/src/')

    def test_iterate_list_from_pointer_field(self):
        o_root = self.offsets['test_pointer_to_list'][0]
        root = self.m.read_struct(o_root, self.ctypes6_gen32.struct_Root)
        self.assertTrue(self.x32_validator.load_members(root, 10))
        # we know its a double linked list, so we can iterate it.
        dnodes = [el for el in self.x32_validator.iterate_list_from_pointer_field(root.ptr_to_double_list, 'list')]
        # test that we have a list of two allocators in a list
        self.assertEqual(len(dnodes), 3)
        for el in dnodes:
            self.assertIsInstance(el, self.ctypes6_gen32.struct_Node)
        snodes = [el for el in self.x32_validator.iterate_list_from_pointer_field(root.ptr_to_single_node, 'entry')]
        self.assertEqual(len(snodes), 3)
        for el in snodes:
            self.assertIsInstance(el, self.ctypes6_gen32.struct_single_node)
        return

    def test_iterate_list_from_field(self):
        o_root = self.offsets['test1'][0]
        usual = self.m.read_struct(o_root, self.ctypes6_gen32.struct_usual)
        self.assertTrue(self.x32_validator.load_members(usual, 10))
        # we want the list of 2 nodes
        dnodes_addrs = [ el for el in self.x32_validator.iterate_list_from_field(usual, 'root')]
        self.assertEqual(len(dnodes_addrs), 2)
        for el in self.x32_validator.iterate_list_from_field(usual, 'root'):
            self.assertIsInstance(el, self.ctypes6_gen32.struct_Node)

        return

    def test_iter(self):
        self.assertTrue(self.x32_validator.load_members(self.usual, 10))
        # we know its a double linked list, so we can iterate it.
        nodes_addrs = [
            el for el in self.x32_validator._iterate_double_linked_list(self.usual.root)]
        # test that we have a list of two allocators in a list
        self.assertEqual(len(nodes_addrs), 2)
        return

    def test_iter_complex(self):
        # we know its a double linked list, so we can iterate it.
        nodes_A = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootA.list)]
        # non repeat the root
        self.assertEqual(len(nodes_A), 6)
        # no dups
        self.assertEqual(len(nodes_A), len(set(nodes_A)))
        self.assertNotIn(self.o_rootA, nodes_A)

        nodes_B = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootB.list)]
        # blink and flink in a tree
        self.assertEqual(len(nodes_B), 14)
        # no dups
        self.assertEqual(len(nodes_B), len(set(nodes_B)))
        self.assertNotIn(self.o_rootB, nodes_B)

        nodes_C = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootC.list)]
        # blink and flink in a tree
        self.assertEqual(len(nodes_C), 31)
        # no dups
        self.assertEqual(len(nodes_C), len(set(nodes_C)))
        self.assertNotIn(self.o_rootC, nodes_C)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
