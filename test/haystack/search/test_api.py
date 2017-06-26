#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import pickle
import unittest

from haystack import constraints
from haystack.search import api
from mappings import folder
from test.haystack import SrcTests


class TestFunction(unittest.TestCase):
    def test_outputs(self):
        with self.assertRaises(TypeError):
            api.output_to_json(None, None)
        with self.assertRaises(TypeError):
            api.output_to_python(None, None)
        with self.assertRaises(TypeError):
            api.output_to_string(None, None)


class _ApiTest(SrcTests):
    """
    Basic loading of a memory dump and offsets values for all tests.
    """
    memdumpname = ''
    modulename = ""

    @classmethod
    def setUpClass(cls):
        cls.memory_handler = folder.load(cls.memdumpname)
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
        results = api.search_record(self.memory_handler, self.ctypes3.struct_test3)
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
        results = api.search_record(self.memory_handler, self.ctypes3.struct_test3, my_constraints)
        # all valid record addresses are in self.offsets
        valid = self.offsets['test3']
        self.assertEqual(len(results), len(valid))
        for record, addr in results:
            self.assertIn(addr, valid)

        # search struct_Node with constraints
        results = api.search_record(self.memory_handler, self.ctypes3.struct_Node, my_constraints)
        # check the string output
        out = api.output_to_string(self.memory_handler, results)
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
            instance, validated = api.load_record(self.memory_handler, self.ctypes3.struct_test3, x)
            self.assertTrue(validated)
            self.assertEqual(instance.val1, 0xdeadbeef)
            self.assertEqual(instance.val1b, 0xdeadbeef)
            self.assertEqual(instance.val2, 0x10101010)
            self.assertEqual(instance.val2b, 0x10101010)
            self.assertEqual(self.my_utils.get_pointee_address(instance.me), x)

        valid = self.offsets['test1']
        for x in valid:
            instance, validated = api.load_record(self.memory_handler, self.ctypes3.struct_Node, x)
            self.assertTrue(validated)
            self.assertEqual(instance.val1, 0xdeadbeef)
            self.assertEqual(self.my_utils.get_pointee_address(instance.ptr1), x)
            self.assertEqual(self.my_utils.get_pointee_address(instance.ptr2), x)

class TestCTypes3_x32(TestCTypes3_x64):

    memdumpname = 'test/src/test-ctypes3.32.dump'
    modulename = "test.src.ctypes3_gen32"

    def test_search(self):
        results = api.search_record(self.memory_handler, self.ctypes3.struct_test3)
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

    def test_weird_py3_bug(self):
        # RESULT: PY3 pickling works if model includes all pythoned module hierachy

        results, validated = api.load_record(self.memory_handler, self.usual, self.address1)
        # check the string output
        retstr = api.output_to_string(self.memory_handler, [(results, validated)])
        self.assertTrue(isinstance(retstr, str))
        ret = api.output_to_python(self.memory_handler, [(results, validated)])
        # check subclass in model module
        x = pickle.dumps(ret)
        # Python 2
        # self.assertIn(b'test.src.ctypes6_gen32.struct_usual_py', x)
        # Python 3
        self.assertIn(b'struct_usual_py', x)
        # TODO TEST really, you should be able to load the pickled code as long as haystack.outputters.python is there
        # and still be able to load the object graph.
        obj = pickle.loads(x)
        self.assertEqual(obj[0][0].root.blink, obj[0][0].root.flink)
        self.assertEqual(obj[0][0].root.blink.flink, obj[0][0].root.flink.flink)
        return

    def test_refresh(self):
        #handler = constraints.ConstraintsConfigHandler()
        #my_constraints = handler.read('test/src/ctypes6.constraints')
        #results = api.search_record(self.memory_handler, self.usual_structname, my_constraints)
        # search struct_usual with constraints
        results, validated = api.load_record(self.memory_handler, self.usual, self.address1)
        # check the string output
        retstr = api.output_to_string(self.memory_handler, [(results, validated)])
        self.assertTrue(isinstance(retstr, str))

        # string
        #retstr = api.show_dumpname(self.usual_structname, self.memdumpname,
        #                                self.address1, rtype='string')
        self.assertIn(str(0x0aaaaaaa), retstr)  # 0xaaaaaaa/178956970L
        self.assertIn(str(0x0ffffff0), retstr)
        self.assertIn('"val2b": 0', retstr)
        self.assertIn('"val1b": 0', retstr)

        # usual->root.{f,b}link = &node1->list; # offset list is (wordsize) bytes
        ## TU results based on __book
        node1_list_addr = hex(self.address2 + self.my_target.get_word_size())
        self.assertIn('"flink": { # <struct_entry at %s' % node1_list_addr, retstr)
        self.assertIn('"blink": { # <struct_entry at %s' % node1_list_addr, retstr)
        ## TU results based on direct access
        #node1_list_addr = self.address2 + self.my_target.get_word_size()
        #self.assertIn('"flink": 0x%0.8x' % node1_list_addr, retstr)
        #self.assertIn('"blink": 0x%0.8x' % node1_list_addr, retstr)

        # python
        usuals = api.output_to_python(self.memory_handler, [(results, validated)])
        usual, validated = usuals[0]
        self.assertEqual(validated, True)
        self.assertEqual(usual.val1, 0x0aaaaaaa)
        self.assertEqual(usual.val2, 0x0ffffff0)
        self.assertEqual(usual.txt, b'This a string with a test this is a test string')

        # so now we got python objects
        # that is node 1
        self.assertIsNotNone(usual.root.flink)
        self.assertEqual(usual.root.flink, usual.root.blink)
        #print usual.root.flink
        # that is node2
        self.assertEqual(usual.root.blink.flink, usual.root.flink.flink)
        # that is None (root.flink = root.blink)
        self.assertIsNone(usual.root.blink.blink)
        self.assertIsNone(usual.root.flink.blink)
        # that is None per design UT
        self.assertIsNone(usual.root.blink.flink.flink)

        # python 2 struct Node
        results, validated = api.load_record(self.memory_handler, self.node, self.address2)
        node1s = api.output_to_python(self.memory_handler, [(results, validated)])
        node1, validated = node1s[0]
        self.assertEqual(validated, True)
        self.assertEqual(node1.val1, 0xdeadbeef)
        self.assertEqual(node1.val2, 0xffffffff)

        results, validated = api.load_record(self.memory_handler, self.node, self.address3)
        node2s = api.output_to_python(self.memory_handler, [(results, validated)])
        node2, validated = node2s[0]
        self.assertEqual(validated, True)
        self.assertEqual(node2.val1, 0xdeadbabe)
        self.assertEqual(node2.val2, 0xffffffff)

        self.assertIsNotNone(usual.root.flink)

        # FIXME this was assertNotEquals. Why would the python obj be equals now ?
        # but we have different instances/references between calls to
        # show_dumpname
        self.assertEqual(usual.root.flink, node1.list)
        self.assertEqual(usual.root.blink.flink, node2.list)

    def test_search(self):
        handler = constraints.ConstraintsConfigHandler()
        my_constraints = handler.read('test/src/ctypes6.constraints')
        results = api.search_record(self.memory_handler, self.node, my_constraints)
        # 2 from test1
        # 3 from test_pointer_to_list
        # the rest have bad values in constrainged fields
        self.assertEqual(len(results), 2 + 3)
        # FIXME: that is a weird idea, that allocations are ordered that way
        (node1, offset1), (node2, offset2) = results[:2]
        self.assertEqual(node1.val1, 0xdeadbeef)
        self.assertEqual(node1.val2, 0xffffffff)
        self.assertEqual(node2.val1, 0xdeadbabe)
        self.assertEqual(node2.val2, 0xffffffff)

        # FIXME there is a circular reference in json.
        #with self.assertRaises(ValueError):
        #    api.output_to_json(self.memory_handler, results)
        #self.assertEqual(node2s['val1'], 0xdeadbabe)
        #self.assertEqual(node2s['val2'], 0xffffffff)
        model = self.memory_handler.get_model()
        #import code
        #code.interact(local=locals())
        x = api.output_to_pickle(self.memory_handler, results)
        rest = pickle.loads(x)
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
