#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest
from haystack import model
from haystack import target
from haystack import types
from haystack.mappings import process

import ConfigParser


class TestCopyModule(unittest.TestCase):


    def test_register_module(self):
        """
        Register module allows for python types to be created next to ctypes structures.
        :return:
        """
        _memory_handler= process.readLocalProcessMappings()
        my_target = _memory_handler.get_target_platform()
        my_model = model.Model(_memory_handler)
        config = ConfigParser.RawConfigParser()
        config.read('test/structures/good.constraints')

        try:
            good = types.import_module_for_target_platform("test.structures.good", my_target)
            good_gen = types.import_module_for_target_platform("test.structures.good_gen", my_target)
            bad_gen = types.import_module_for_target_platform("test.structures.bad_gen", my_target)
            # copy bad_gen in good
            my_model.copy_generated_classes(bad_gen, good)
            my_model.copy_generated_classes(good_gen, good)
            self.assertIn('Struct1', good.__dict__.keys())
            self.assertIn('Struct2', good.__dict__)
            self.assertNotIn('Struct1_py', good.__dict__)
            self.assertNotIn('expectedValues', good.Struct1.__dict__)
        except ImportError as e:
            self.fail(e)
        try:
            bad = types.import_module_for_target_platform("test.structures.bad", my_target)
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
        my_model.register_module(bad)
        self.assertIn('Struct1_py', bad.__dict__)
        self.assertIn('expectedValues', bad.Struct1.__dict__)
        # POPO is not create in good
        self.assertNotIn('Struct1_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        my_model.register_module(good)  # creates POPO for the rest
        self.assertIn('Struct2_py', good.__dict__)
        self.assertIn('expectedValues', good.Struct1.__dict__)
        # expectedValues is in a function
        self.assertNotIn('expectedValues', good.Struct2.__dict__)

        # add an expectedValues
        good.populate()
        self.assertIn('expectedValues', good.Struct1.__dict__)
        self.assertIn('expectedValues', good.Struct2.__dict__)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig( stream=sys.stderr, level=logging.INFO )
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
