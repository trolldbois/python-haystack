#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for haystack.reverse.structure."""

import unittest
import logging

from haystack.reverse.heuristics import radare
from test.testfiles import zeus_856_svchost_exe


@unittest.skip
class TestRadare(unittest.TestCase):

    def setUp(self):
        from haystack import dump_loader
        self.memory_handler = dump_loader.load(zeus_856_svchost_exe.dumpname)
        pass

    def tearDown(self):
        self.memory_handler.reset_mappings()
        self.memory_handler = None

    def test_radare(self):
        finder = self.memory_handler.get_heap_finder()
        mappings = self.memory_handler.get_mappings()
        heaps = finder.get_heap_mappings()

        mapping = self.memory_handler.get_mapping_for_address(0x00b70000)

        r2 = radare.RadareAnalysis(self.memory_handler)
        r2.find_functions(mapping)

        r2.init_all_functions()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('radare').setLevel(level=logging.DEBUG)
    # logging.getLogger("test_fieldtypes").setLevel(level=logging.DEBUG)
    # logging.getLogger("structure").setLevel(level=logging.DEBUG)
    # logging.getLogger("field").setLevel(level=logging.DEBUG)
    # logging.getLogger("dsa").setLevel(level=logging.DEBUG)
    # logging.getLogger("re_string").setLevel(level=logging.DEBUG)
    unittest.main(verbosity=2)
    #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
    # unittest.TextTestRunner(verbosity=2).run(suite)
