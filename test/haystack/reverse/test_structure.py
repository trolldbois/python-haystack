#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import logging
import unittest

import os

from haystack.reverse import context

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger("test_structure")


class TestStructure(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        from haystack.reverse.heuristics import dsa
        self.context = context.get_context('test/src/test-ctypes3.32.dump')
        self.target = self.context.memory_handler.get_target_platform()
        self.dsa = dsa.DSASimple(self.target)
        self.pta = dsa.EnrichedPointerFields(self.target)
        pass

    def setUp(self):
        pass

    def tearDown(self):
        #self.context = None
        self.context.reset()
        pass

    def test_decodeFields(self):
        for s in self.context.listStructures():
            self.dsa.analyze_fields(s)
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s._get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(s.getPointerFields()), 1)
            elif len(s) == 20:  # test3, 1 pointer on create
                # fields, no heuristic to detect medium sized int
                # TODO untyped of size < 8 == int * x
                # print s.toString()
                self.assertEqual(len(s._get_fields()), 3)  # discutable
                self.assertEqual(len(s.getPointerFields()), 1)
        return

    def test_resolvePointers(self):
        for s in self.context.listStructures():
            self.pta.analyze_fields(s)
        self.assertTrue(True)  # test no error

    def test_resolvePointers2(self):
        for s in self.context.listStructures():
            self.dsa.analyze_fields(s)
            self.assertTrue(s.is_resolved())
        for s in self.context.listStructures():
            log.debug('RESOLVATION: %s' % (s.is_resolved()))
            self.pta.analyze_fields(s)
            if len(s) == 12:  # Node + padding, 1 pointer on create
                self.assertEqual(len(s._get_fields()), 3)  # 1, 2 and padding
                self.assertEqual(len(s.getPointerFields()), 1)

    def test_reset(self):
        from haystack.reverse import structure
        for s in self.context.listStructures():
            s.reset()
            if isinstance(s, structure.CacheWrapper):
                members = s.obj().__dict__
            else:
                members = s.__dict__
            for name, value in members.items():
                if name in ['_size', '_context', '_name', '_vaddr']:
                    self.assertNotIn(value, [None, False])
                elif name in ['_dirty']:
                    self.assertTrue(value)
                elif name in ['_fields']:
                    self.assertEquals(value, list())
                elif name in ['dumpname']:
                    self.assertTrue(os.access(value, os.F_OK))
                else:
                    self.assertIn(value, [None, False], name + ' not resetted')

    def test_string_overlap(self):
        context6 = context.get_context('test/src/test-ctypes6.32.dump')
        for s in context6.listStructures():
            # s.resolvePointers()
            self.dsa.analyze_fields(s)
            log.debug(s.toString())
        self.assertTrue(True)  # test no error


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # logging.getLogger("test_structure").setLevel(logging.DEBUG)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main(verbosity=2)
