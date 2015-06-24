#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest
import sys

import haystack

from haystack import argparse_utils


class Test(unittest.TestCase):

    def test_readable(self):
        """test the readable helper."""
        invalid = '/345678ui0d9t921giv9'
        self.assertRaises(ValueError, argparse_utils.readable, invalid)

        valid = sys.modules[__name__].__file__
        self.assertEquals(argparse_utils.readable(valid), valid)
        return

    def test_writeable(self):
        """test the writeable helper."""
        invalid = '/345678ui0d9t921giv9/qwf89/2/4r/ef/23/23g/'
        self.assertRaises(ValueError, argparse_utils.writeable, invalid)

        valid = sys.modules[__name__].__file__
        self.assertEquals(argparse_utils.writeable(valid), valid)
        return

    def test_int16(self):
        """test the int16 helper."""
        invalid = '/345678ui0d9t921giv9'
        self.assertRaises(ValueError, argparse_utils.int16, invalid)
        invalid = sys.modules[__name__].__file__
        self.assertRaises(ValueError, argparse_utils.int16, invalid)

        valid = '0x01293'
        self.assertEquals(argparse_utils.int16(valid), 0x01293)
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    #logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(level=logging.DEBUG)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
