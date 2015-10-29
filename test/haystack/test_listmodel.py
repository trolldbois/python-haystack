#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.listmodel ."""

import logging
import unittest
import sys

from haystack import model
from haystack import constraints
from haystack import dump_loader

from test.src import ctypes6
from test.haystack import SrcTests


class TestListStructTest6(SrcTests):
    """
    """

    def setUp(self):
        self.memory_handler = dump_loader.load('test/src/test-ctypes6.32.dump')
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

    def test_iter(self):
        self.assertTrue(self.x32_validator.load_members(self.usual, 10))
        # we know its a double linked list, so we can iterate it.
        nodes_addrs = [
            el for el in self.x32_validator._iterate_double_linked_list(self.usual.root)]
        # test that we have a list of two allocators in a list
        self.assertEquals(len(nodes_addrs), 2)
        return

    def test_iter_complex(self):
        # we know its a double linked list, so we can iterate it.
        nodes_A = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootA.list)]
        # non repeat the root
        self.assertEquals(len(nodes_A), 6)
        # no dups
        self.assertEquals(len(nodes_A), len(set(nodes_A)))
        self.assertNotIn(self.o_rootA, nodes_A)

        nodes_B = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootB.list)]
        # blink and flink in a tree
        self.assertEquals(len(nodes_B), 14)
        # no dups
        self.assertEquals(len(nodes_B), len(set(nodes_B)))
        self.assertNotIn(self.o_rootB, nodes_B)

        nodes_C = [
            el for el in self.x32_validator._iterate_double_linked_list(self.rootC.list)]
        # blink and flink in a tree
        self.assertEquals(len(nodes_C), 31)
        # no dups
        self.assertEquals(len(nodes_C), len(set(nodes_C)))
        self.assertNotIn(self.o_rootC, nodes_C)

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
