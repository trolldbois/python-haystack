#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest
import sys

from haystack import dump_loader
from haystack import model
from haystack import types
from haystack import utils
from haystack.structures.win32 import win7heapwalker


class TestCopyModule(unittest.TestCase):

    def test_registerModule(self):
        from haystack import model
        try:
            from test.structures import good
            from test.structures import good_gen
            from test.structures import bad_gen
            # copy bad_gen in good
            model.copyGeneratedClasses(bad_gen, good)
            model.copyGeneratedClasses(good_gen, good)
            self.assertIn('Struct1', good.__dict__)
            self.assertIn('Struct2', good.__dict__)
            self.assertNotIn('Struct1_py', good.__dict__)
            self.assertNotIn('expectedValues', good.Struct1.__dict__)
        except ImportError as e:
            self.fail(e)
        try:
            from test.structures import bad
            # test if module has members
            self.assertEquals(bad.BLOCK_SIZE, 16)
            self.assertIn('Struct1', bad.__dict__)
            self.assertIn('expectedValues', bad.Struct1.__dict__)
            # same Struct1 object is imported in bad and good
            self.assertIn('expectedValues', good.Struct1.__dict__)
            self.assertNotIn('expectedValues', good.Struct2.__dict__)
        except ImportError as e:
            self.fail(e)

        # test if register works (creates POPO)
        model.registerModule(bad)
        self.assertIn('Struct1_py', bad.__dict__)
        self.assertIn('expectedValues', bad.Struct1.__dict__)
        # POPO is not create in good
        self.assertNotIn('Struct1_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        model.registerModule(good)  # creates POPO for the rest
        self.assertIn('Struct2_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        # expectedValues is in a function
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        # add an expectedValues
        good.populate()
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertIn('expectedValues', good.Struct2.__dict__)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    #logging.basicConfig( stream=sys.stderr, level=logging.INFO )
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
