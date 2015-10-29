#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.model ."""

import logging
import unittest

from haystack import model
from haystack.mappings import process


class TestCopyModule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.memory_handler= process.read_local_process_mappings()
        cls.my_target = cls.memory_handler.get_target_platform()
        cls.my_model = model.Model(cls.memory_handler)

    @classmethod
    def tearDownClass(cls):
        cls.memory_handler.reset_mappings()
        cls.memory_handler = None
        cls.my_target = None
        cls.my_model = None

    def setUp(self):
        self.my_model.reset()

    def tearDown(self):
        self.my_model.reset()

    def test_register_module(self):
        """
        Register module allows for python types to be created as a python friendly
        clone to ctypes allocators.
        """
        bad = self.my_model.import_module("test.structures.bad")
        good = self.my_model.import_module("test.structures.good")

        # register the module
        self.assertNotIn(good, self.my_model.get_pythoned_modules().values())
        self.assertNotIn('Struct2_py', good.__dict__.keys())
        self.my_model.build_python_class_clones(good)
        self.assertIn(good, self.my_model.get_pythoned_modules().values())
        self.assertIn('Struct2_py', good.__dict__.keys())

        self.assertNotIn(bad, self.my_model.get_pythoned_modules().values())
        self.assertNotIn('Struct1_py', bad.__dict__.keys())
        self.my_model.build_python_class_clones(bad)
        self.assertIn(bad, self.my_model.get_pythoned_modules().values())
        self.assertIn(good, self.my_model.get_pythoned_modules().values())
        self.assertIn('Struct1_py', bad.__dict__.keys())

    def test_reset(self):
        """Reset the model cache. All classes should have been removed."""
        good = self.my_model.import_module("test.structures.good")

        self.assertNotIn("test.structures.good", self.my_model.get_pythoned_modules().keys())
        self.assertNotIn(good, self.my_model.get_pythoned_modules().values())
        self.assertNotIn('Struct2_py', good.__dict__.keys())
        self.my_model.build_python_class_clones(good)
        self.assertIn("test.structures.good", self.my_model.get_pythoned_modules().keys())
        self.assertIn(good, self.my_model.get_pythoned_modules().values())
        self.assertIn('Struct2_py', good.__dict__.keys())

        self.my_model.reset()
        self.assertNotIn(good, self.my_model.get_pythoned_modules().values())
        self.assertNotIn("test.structures.good", self.my_model.get_pythoned_modules().keys())
        self.assertIn('Struct2_py', good.__dict__.keys())



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig( stream=sys.stderr, level=logging.INFO )
    # logging.getLogger("listmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("basicmodel").setLevel(level=logging.DEBUG)
    # logging.getLogger("root").setLevel(level=logging.DEBUG)
    # logging.getLogger("win7heap").setLevel(level=logging.DEBUG)
    # logging.getLogger("dump_loader").setLevel(level=logging.INFO)
    # logging.getLogger("memory_mapping").setLevel(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
