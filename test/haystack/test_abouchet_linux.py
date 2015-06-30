#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

import haystack

from haystack import abouchet
from haystack import model
from haystack import types

from test.haystack import SrcTests


class Test7_x32(SrcTests):

    """Validate abouchet API on a linux x32 dump of ctypes7.
    Mainly tests cross-arch c_void_p."""

    def setUp(self):
        model.reset()
        types.reload_ctypes(4, 4, 8)
        self.memdumpname = 'test/src/test-ctypes7.32.dump'
        self.classname = 'test.src.ctypes7.struct_Node'
        self._load_offsets_values(self.memdumpname)
        self.address = self.offsets['test1'][0]  # 0x8f40008
        # load layout in x32
        from test.src import ctypes7
        from test.src import ctypes7_gen32
        model.copyGeneratedClasses(ctypes7_gen32, ctypes7)
        model.registerModule(ctypes7)
        # apply constraints
        ctypes7.populate()

    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.classname = None
        self.address = None
        model.reset()

    def test_refresh(self):
        from test.src import ctypes7
        self.assertEquals(len(ctypes7.struct_Node.expectedValues.keys()), 2)
        # string
        retstr = abouchet.show_dumpname(
            self.classname,
            self.memdumpname,
            self.address,
            rtype='string')
        self.assertIn("3735928559L,", retstr)  # 0xdeadbeef
        self.assertIn("struct_Node at 0x%x>" % (self.address), retstr)
        self.assertIn('"ptr2": 0x%08x' % (self.address), retstr)

        # python
        node, validated = abouchet.show_dumpname(
            self.classname, self.memdumpname, self.address, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node.val1, 0xdeadbeef)
        #self.assertEquals(node.ptr2, self.address)
        self.assertIsNone(node.ptr2)

    def test_search(self):
        from test.src import ctypes7
        self.assertEquals(len(ctypes7.struct_Node.expectedValues.keys()), 2)

        retstr = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            rtype='string')
        self.assertIn("3735928559L,", retstr)
        self.assertIn("struct_Node at 0x%x>" % (self.address), retstr)
        self.assertIn('"ptr2": 0x%08x' % (self.address), retstr)

        # python
        results = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            rtype='python')
        self.assertEquals(len(results), 1)
        for node, offset in results:
            self.assertEquals(offset, self.address)
            self.assertEquals(node.val1, 0xdeadbeef)
            #self.assertEquals(node.ptr2, self.address)
            self.assertIsNone(node.ptr2)

        # python
        results = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            maxnum=10,
            rtype='python')
        self.assertEquals(len(results), 1)
        for node, offset in results:
            self.assertEquals(offset, self.address)
            self.assertEquals(node.val1, 0xdeadbeef)
            #self.assertEquals(node.ptr2, self.address)
            self.assertIsNone(node.ptr2)
        return


class Test7_x64(SrcTests):

    """Validate abouchet API on a linux x64 dump of ctypes7.
    Mainly tests cross-arch c_void_p."""

    def setUp(self):
        model.reset()
        types.reload_ctypes(8, 8, 16)
        self.memdumpname = 'test/src/test-ctypes7.64.dump'
        self.classname = 'test.src.ctypes7.struct_Node'
        self._load_offsets_values(self.memdumpname)
        self.address = self.offsets['test1'][0]  # 0x000000001b1e010
        # load layout in x64
        from test.src import ctypes7
        from test.src import ctypes7_gen64
        model.copyGeneratedClasses(ctypes7_gen64, ctypes7)
        model.registerModule(ctypes7)
        # apply constraints
        ctypes7.populate()

    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.classname = None
        self.address = None
        model.reset()

    def test_refresh(self):
        import ctypes
        from test.src import ctypes7
        self.assertEquals(ctypes.sizeof(ctypes7.struct_Node), 16)
        self.assertEquals(len(ctypes7.struct_Node.expectedValues.keys()), 2)
        # string
        retstr = abouchet.show_dumpname(
            self.classname,
            self.memdumpname,
            self.address,
            rtype='string')
        self.assertIn("3735928559L,", retstr)
        self.assertIn("struct_Node at 0x%x>" % (self.address), retstr)
        self.assertIn('"ptr2": 0x%016x' % (self.address), retstr)

        # python
        node, validated = abouchet.show_dumpname(
            self.classname, self.memdumpname, self.address, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node.val1, 0xdeadbeef)
        #self.assertEquals(node.ptr2, self.address)
        self.assertIsNone(node.ptr2)

    def test_search(self):
        import ctypes
        from test.src import ctypes7
        self.assertEquals(ctypes.sizeof(ctypes7.struct_Node), 16)
        self.assertEquals(len(ctypes7.struct_Node.expectedValues.keys()), 2)

        retstr = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            rtype='string')
        self.assertIn("3735928559L,", retstr)
        self.assertIn("struct_Node at 0x%x>" % (self.address), retstr)
        self.assertIn('"ptr2": 0x%016x' % (self.address), retstr)

        # python
        results = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            rtype='python')
        self.assertEquals(len(results), 1)
        for node, offset in results:
            self.assertEquals(offset, self.address)
            self.assertEquals(node.val1, 0xdeadbeef)
            #self.assertEquals(node.ptr2, self.address)
            self.assertIsNone(node.ptr2)

        return
        # python
        results = abouchet.search_struct_dumpname(
            self.classname,
            self.memdumpname,
            maxnum=10,
            rtype='python')
        self.assertEquals(len(results), 1)
        for node, offset in results:
            self.assertEquals(offset, self.address)
            self.assertEquals(node.val1, 0xdeadbeef)
            #self.assertEquals(node.ptr2, self.address)
            self.assertIsNone(node.ptr2)
        return


class Test6_x32(SrcTests):

    """Validate abouchet API on a linux x32 dump of ctypes6.
    Mainly tests cross-arch POINTER to structs and c_char_p.

    Debugs a lot of bugs with references book.
    """

    def setUp(self):
        import sys
        model.reset()
        types.reload_ctypes(4, 4, 8)
        self.memdumpname = 'test/src/test-ctypes6.32.dump'
        self.node_structname = 'test.src.ctypes6.struct_Node'
        self.usual_structname = 'test.src.ctypes6.struct_usual'
        self._load_offsets_values(self.memdumpname)
        self.address1 = self.offsets['test1'][0]  # struct_usual
        self.address2 = self.offsets['test2'][0]  # struct_Node
        self.address3 = self.offsets['test3'][0]  # struct_Node
        # load layout in x32
        from test.src import ctypes6
        from test.src import ctypes6_gen32
        model.copyGeneratedClasses(ctypes6_gen32, ctypes6)
        model.registerModule(ctypes6)
        # apply constraints
        ctypes6.populate()

    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.node_structname = None
        self.usual_structname = None
        self.address1 = None
        self.address2 = None
        self.address3 = None
        model.reset()

    def test_refresh(self):
        # if you delete the Heap memorymap,
        # all references in the model are invalided

        # real problem: references left over by previous search.
        # solution: move the book into memory_mappings,

        from test.src import ctypes6
        self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)

        # string
        retstr = abouchet.show_dumpname(self.usual_structname, self.memdumpname,
                                        self.address1, rtype='string')
        if True:
            import ctypes
            self.assertIn('CTypesProxy-4:4:12', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 4)
        self.assertIn(str(0x0aaaaaaa), retstr)  # 0xaaaaaaa/178956970L
        self.assertIn(str(0x0ffffff0), retstr)
        self.assertIn('"val2b": 0L,', retstr)
        self.assertIn('"val1b": 0L,', retstr)
        # print retstr

        # usual->root.{f,b}link = &node1->list; # offset list is 4 bytes
        node1_list_addr = hex(self.address2 + 4)
        self.assertIn(
            '"flink": { # <struct_entry at %s' %
            (node1_list_addr),
            retstr)
        self.assertIn(
            '"blink": { # <struct_entry at %s' %
            (node1_list_addr),
            retstr)

        # python
        usual, validated = abouchet.show_dumpname(self.usual_structname,
                                                  self.memdumpname,
                                                  self.address1, rtype='python')
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
        node1, validated = abouchet.show_dumpname(self.node_structname,
                                                  self.memdumpname,
                                                  self.address2, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)

        node2, validated = abouchet.show_dumpname(self.node_structname,
                                                  self.memdumpname,
                                                  self.address3, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)

        self.assertIsNotNone(usual.root.flink)

        # but we have different instances/references between calls to
        # show_dumpname
        self.assertNotEquals(usual.root.flink, node1.list)
        self.assertNotEquals(usual.root.blink.flink, node2.list)

        # TODO the listmodel test should test if references have been loaded
        # without searching for them.
        if True:
            import ctypes
            self.assertIn('CTypesProxy-4:4:12', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 4)

    def test_search(self):
        if True:
            import ctypes
            self.assertIn('CTypesProxy-4:4:8', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 4)
        from test.src import ctypes6
        self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)

        retstr = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            rtype='string')
        self.assertIn("3735928559L,", retstr)  # 0xdeadbeef
        self.assertIn(hex(self.address2), retstr)

        # python
        results = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            rtype='python')
        self.assertEquals(len(results), 1)

        # python nultiple results
        results = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            maxnum=10,
            rtype='python')
        self.assertEquals(len(results), 2)
        (node1, offset1), (node2, offset2) = results
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)
        if True:
            import ctypes
            self.assertIn('CTypesProxy-4:4:12', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 4)
        return


class Test6_x64(SrcTests):

    """Validate abouchet API on a linux x64 dump of ctypes6.
    Mainly tests cross-arch POINTER to structs and c_char_p."""

    def setUp(self):
        model.reset()
        types.reload_ctypes(8, 8, 16)
        self.memdumpname = 'test/src/test-ctypes6.64.dump'
        self.node_structname = 'test.src.ctypes6.struct_Node'
        self.usual_structname = 'test.src.ctypes6.struct_usual'
        self._load_offsets_values(self.memdumpname)
        self.address1 = self.offsets['test1'][0]  # struct_usual
        self.address2 = self.offsets['test2'][0]  # struct_Node
        self.address3 = self.offsets['test3'][0]  # struct_Node
        # load layout in x64
        from test.src import ctypes6
        from test.src import ctypes6_gen64
        model.copyGeneratedClasses(ctypes6_gen64, ctypes6)
        model.registerModule(ctypes6)
        # apply constraints
        ctypes6.populate()

    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.node_structname = None
        self.usual_structname = None
        self.address1 = None
        self.address2 = None
        self.address3 = None
        model.reset()

    def test_refresh(self):
        from test.src import ctypes6
        self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)
        # string
        retstr = abouchet.show_dumpname(self.usual_structname, self.memdumpname,
                                        self.address1, rtype='string')
        if True:
            import ctypes
            self.assertIn('CTypesProxy-8:8:16', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 8)

        self.assertIn(str(0x0aaaaaaa), retstr)  # 0xaaaaaaa/178956970L
        self.assertIn(str(0x0ffffff0), retstr)
        self.assertIn('"val2b": 0L,', retstr)
        self.assertIn('"val1b": 0L,', retstr)

        # usual->root.{f,b}link = &node1->list; # offset list is 8 bytes
        # 64 bits alignement
        node1_list_addr = hex(self.address2 + 8)
        self.assertIn(
            '"flink": { # <struct_entry at %s' %
            (node1_list_addr),
            retstr)
        self.assertIn(
            '"blink": { # <struct_entry at %s' %
            (node1_list_addr),
            retstr)

        # python
        usual, validated = abouchet.show_dumpname(self.usual_structname,
                                                  self.memdumpname,
                                                  self.address1, rtype='python')
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
        node1, validated = abouchet.show_dumpname(self.node_structname,
                                                  self.memdumpname,
                                                  self.address2, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)

        node2, validated = abouchet.show_dumpname(self.node_structname,
                                                  self.memdumpname,
                                                  self.address3, rtype='python')
        self.assertEquals(validated, True)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)

        self.assertIsNotNone(usual.root.flink)

        # but we have different instances/references between calls to
        # show_dumpname
        self.assertNotEquals(usual.root.flink, node1.list)
        self.assertNotEquals(usual.root.blink.flink, node2.list)

        if True:
            import ctypes
            self.assertIn('CTypesProxy-8:8:16', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 8)

    def test_search(self):
        if True:
            import ctypes
            self.assertIn('CTypesProxy-8:8:16', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 8)
        from test.src import ctypes6
        self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)

        retstr = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            rtype='string')
        self.assertIn("3735928559L,", retstr)  # 0xdeadbeef
        self.assertIn(hex(self.address2), retstr)

        # python
        results = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            rtype='python')
        self.assertEquals(len(results), 1)

        # python nultiple results
        results = abouchet.search_struct_dumpname(
            self.node_structname,
            self.memdumpname,
            maxnum=10,
            rtype='python')
        self.assertEquals(len(results), 2)
        (node1, offset1), (node2, offset2) = results
        self.assertEquals(node1.val1, 0xdeadbeef)
        self.assertEquals(node1.val2, 0xffffffff)
        self.assertEquals(node2.val1, 0xdeadbabe)
        self.assertEquals(node2.val2, 0xffffffff)
        if True:
            import ctypes
            self.assertIn('CTypesProxy-8:8:16', '%s' % ctypes)
            self.assertEquals(ctypes.sizeof(ctypes.c_long), 8)
        return


#@unittest.skip('')
class TestApiLinuxDumpX64(unittest.TestCase):

    """Validate API on a linux x64 dump of SSH."""

    def setUp(self):
        model.reset()
        self.validAddress = '0x7f724c90d740'
        self.memdumpname = 'test/dumps/ssh/ssh.x64.6653.dump'
        self.classname = 'sslsnoop.ctypes_openssh.session_state'
        self.known_heap = (0x00007f724c905000, 249856)
        try:
            import sslsnoop
        except ImportError:
            self.skipTest('sslsnoop not present')


    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.validAddress = None
        self.classname = None
        self.known_heap = None
        model.reset()

    def test_show(self):
        instance, validated = abouchet.show_dumpname(
            self.classname, self.memdumpname, long(
                self.validAddress, 16))
        self.assertIsInstance(instance, object)
        self.assertEquals(instance.connection_in, 3)
        # print instance.__dict__
        #self.assertEquals(instance.VirtualMemoryThreshold, 0xfe00)
        #self.assertEquals(instance.FrontEndHeapType, 0)
        # self.assertTrue(validated)
        return


#@unittest.skip('')
class TestApiLinuxDump(unittest.TestCase):

    """ test is the python API works. """

    def setUp(self):
        model.reset()
        self.memdumpname = 'test/dumps/ssh/ssh.1'
        self.classname = 'sslsnoop.ctypes_openssh.session_state'
        self.known_heaps = [(0xb84ee318, 0)
                            ]
        try:
            import sslsnoop
        except ImportError:
            self.skipTest('sslsnoop not present')


    def tearDown(self):
        super(SrcTests,self).tearDown()
        self.memdumpname = None
        self.classname = None
        self.known_heap = None
        model.reset()

    def test_show(self):
        instance, validated = abouchet.show_dumpname(
            self.classname, self.memdumpname, self.known_heaps[0][0])
        self.assertTrue(validated)
        self.assertIsInstance(instance, object)
        self.assertEquals(instance.connection_in, 3)
        self.assertEquals(instance.connection_out, 3)
        self.assertEquals(instance.receive_context.evp.cipher.block_size, 16)
        self.assertEquals(instance.receive_context.evp.cipher.key_len, 16)
        self.assertEquals(instance.receive_context.evp.cipher.iv_len, 16)
        self.assertEquals(instance.receive_context.evp.key_len, 16)
        self.assertEquals(instance.receive_context.cipher.name, 'aes128-ctr')
        self.assertEquals(instance.receive_context.cipher.block_size, 16)
        self.assertEquals(instance.receive_context.cipher.key_len, 16)

        self.assertEquals(instance.send_context.evp.cipher.block_size, 16)
        self.assertEquals(instance.send_context.evp.cipher.key_len, 16)
        self.assertEquals(instance.send_context.evp.cipher.iv_len, 16)
        self.assertEquals(instance.send_context.evp.key_len, 16)
        self.assertEquals(instance.send_context.cipher.name, 'aes128-ctr')
        self.assertEquals(instance.send_context.cipher.block_size, 16)
        self.assertEquals(instance.send_context.cipher.key_len, 16)

        return


if __name__ == '__main__':
    import sys
    logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
    #logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(level=logging.DEBUG)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
