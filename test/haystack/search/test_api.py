#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest

import haystack
from haystack import dump_loader
from haystack import constraints
from haystack.search import api
from test.haystack import SrcTests


class _ApiTest(SrcTests):
    """
    Basic loading of a memory dump and offsets values for all tests.
    """
    memdumpname = ''
    modulename = ""

    @classmethod
    def setUpClass(cls):
        cls.memory_handler = dump_loader.load(cls.memdumpname)
        cls.my_target = cls.memory_handler.get_target_platform()
        cls.my_ctypes = cls.my_target.get_target_ctypes()
        cls.my_utils = cls.my_target.get_target_ctypes_utils()
        cls.my_model = cls.memory_handler.get_model()
        # load offsets
        cls._load_offsets_values(cls.memdumpname)

    @classmethod
    def tearDownClass(cls):
        cls.memdumpname = None
        cls.my_target = None
        cls.my_ctypes = None
        cls.my_utils = None
        cls.my_model = None
        del cls.memory_handler
        cls.memory_handler = None

    # inherit def tearDown(self):


class TestCTypes3_x64(_ApiTest):

    memdumpname = 'test/src/test-ctypes3.64.dump'
    modulename = "test.src.ctypes3_gen64"

    def setUp(self):
        self.ctypes3 = self.my_model.import_module(self.modulename)

    def tearDown(self):
        self.ctypes3 = None

    def test_search(self):
        results = haystack.search_record(self.memory_handler, self.ctypes3.struct_test3)
        # without constraints, struct_test3 could be mapped pretty much anywhere in x64
        # all valid record addresses are in self.offsets
        valid = self.offsets['test1'] + self.offsets['test3']
        self.assertEqual(len(results), len(valid))
        for record, addr in results:
            self.assertIn(addr, valid)

    def test_search_with_constraints(self):
        # now add some constraints to the search for struct_test3
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read('test/src/ctypes3.constraints')
        results = haystack.search_record(self.memory_handler, self.ctypes3.struct_test3, my_constraints)
        # all valid record addresses are in self.offsets
        valid = self.offsets['test3']
        self.assertEqual(len(results), len(valid))
        for record, addr in results:
            self.assertIn(addr, valid)

        # search struct_Node with constraints
        results = haystack.search_record(self.memory_handler, self.ctypes3.struct_Node, my_constraints)
        # check the string output
        out = haystack.output_to_string(self.memory_handler, results)
        valid = self.offsets['test1']
        self.assertEqual(len(results), len(valid))
        for x in valid:
            self.assertIn(hex(x), out)
        # all valid record addresses are in self.offsets
        for record, addr in results:
            self.assertIn(addr, valid)

    def test_load(self):
        valid = self.offsets['test3']
        for x in valid:
            instance, validated = haystack.search.api.load_record(self.memory_handler, self.ctypes3.struct_test3, x)
            self.assertTrue(validated)
            self.assertEqual(instance.val1, 0xdeadbeef)
            self.assertEqual(instance.val1b, 0xdeadbeef)
            self.assertEqual(instance.val2, 0x10101010)
            self.assertEqual(instance.val2b, 0x10101010)
            self.assertEqual(self.my_utils.get_pointee_address(instance.me), x)

        valid = self.offsets['test1']
        for x in valid:
            instance, validated = haystack.search.api.load_record(self.memory_handler, self.ctypes3.struct_Node, x)
            self.assertTrue(validated)
            self.assertEqual(instance.val1, 0xdeadbeef)
            self.assertEqual(self.my_utils.get_pointee_address(instance.ptr1), x)
            self.assertEqual(self.my_utils.get_pointee_address(instance.ptr2), x)

class TestCTypes3_x32(TestCTypes3_x64):

    memdumpname = 'test/src/test-ctypes3.32.dump'
    modulename = "test.src.ctypes3_gen32"

    def test_search(self):
        results = haystack.search_record(self.memory_handler, self.ctypes3.struct_test3)
        # without constraints, struct_test3 can only be mapped correctly to sutrc_test3.
        # struct_node is too small in x32
        valid = self.offsets['test3']
        self.assertEqual(len(results), len(valid))
        for record, addr in results:
            self.assertIn(addr, valid)


class Test6_x32(_ApiTest):

    """Validate abouchet API on a linux x32 dump of ctypes6.
    Mainly tests cross-arch POINTER to structs and c_char_p.

    Debugs a lot of bugs with references book.
    """

    memdumpname = 'test/src/test-ctypes6.32.dump'
    modulename = "test.src.ctypes6_gen32"

    def setUp(self):
        self.ctypes6 = self.my_model.import_module(self.modulename)
        self.node = self.ctypes6.struct_Node
        self.usual = self.ctypes6.struct_usual
        self.address1 = self.offsets['test1'][0]  # struct_usual
        self.address2 = self.offsets['test2'][0]  # struct_Node
        self.address3 = self.offsets['test3'][0]  # struct_Node

    def tearDown(self):
        super(Test6_x32, self).tearDown()
        self.ctypes6 = None
        self.node = None
        self.usual = None
        self.address1 = None
        self.address2 = None
        self.address3 = None

    def test_refresh(self):
        #handler = constraints.ConstraintsConfigHandler()
        #my_constraints = handler.read('test/src/ctypes6.constraints')
        #results = haystack.search_record(self.memory_handler, self.usual_structname, my_constraints)
        # search struct_usual with constraints
        results, validated = haystack.search.api.load_record(self.memory_handler, self.usual, self.address1)
        # check the string output
        retstr = haystack.output_to_string(self.memory_handler, [(results, validated)])

        # string
        #retstr = api.show_dumpname(self.usual_structname, self.memdumpname,
        #                                self.address1, rtype='string')
        self.assertIn(str(0x0aaaaaaa), retstr)  # 0xaaaaaaa/178956970L
        self.assertIn(str(0x0ffffff0), retstr)
        self.assertIn('"val2b": 0L,', retstr)
        self.assertIn('"val1b": 0L,', retstr)
        # print retstr

        # usual->root.{f,b}link = &node1->list; # offset list is (wordsize) bytes
        node1_list_addr = hex(self.address2 + self.my_target.get_word_size())
        self.assertIn('"flink": { # <struct_entry at %s' % node1_list_addr, retstr)
        self.assertIn('"blink": { # <struct_entry at %s' % node1_list_addr, retstr)

        # python
        usuals = haystack.output_to_python(self.memory_handler, [(results, validated)])
        usual, validated = usuals[0]
        self.assertEquals(validated, True)
        self.assertEquals(usual.val1, 0x0aaaaaaa)
        self.assertEquals(usual.val2, 0x0ffffff0)
        self.assertEquals(usual.txt, 'This a string with a test this is a test '
                                     'string')

        # so now we got python objects
        # that is node 1
        self.assertIsNotNone(usual.root.flink)
        self.assertEquals(usual.root.flink, usual.root.blink)
        # that is node2
        self.assertEquals(usual.root.blink.flink, usual.root.flink.flink)
        # that is None (root.flink = root.blink)
        self.assertIsNone(usual.root.blink.blink)
        self.assertIsNone(usual.root.flink.blink)
        # that is None per design UT
        self.assertIsNone(usual.root.blink.flink.flink)

        # python 2 struct Node
        results, validated = haystack.search.api.load_record(self.memory_handler, self.node, self.address2)
        node1s = haystack.output_to_python(self.memory_handler, [(results, validated)])
        node1, validated = node1s[0]
        self.assertEquals(validated, True)
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)

        results, validated = haystack.search.api.load_record(self.memory_handler, self.node, self.address3)
        node2s = haystack.output_to_python(self.memory_handler, [(results, validated)])
        node2, validated = node2s[0]
        self.assertEquals(validated, True)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)

        self.assertIsNotNone(usual.root.flink)

        # FIXME this was assertNotEquals. Why would the python obj be equals now ?
        # but we have different instances/references between calls to
        # show_dumpname
        self.assertEquals(usual.root.flink, node1.list)
        self.assertEquals(usual.root.blink.flink, node2.list)

    def test_search(self):
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read('test/src/ctypes6.constraints')
        results = haystack.search_record(self.memory_handler, self.node, my_constraints)
        self.assertEquals(len(results), 2)
        (node1, offset1), (node2, offset2) = results
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)
        return


class Test6_x64(Test6_x32):
    """Validate abouchet API on a linux x64 dump of ctypes6.
    Mainly tests cross-arch POINTER to structs and c_char_p."""

    memdumpname = 'test/src/test-ctypes6.64.dump'
    modulename = "test.src.ctypes6_gen64"


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.getLogger('searcher').setLevel(logging.DEBUG)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
