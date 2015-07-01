#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import numpy
import os
import unittest

from haystack import model
from haystack.reverse import utils
from haystack.reverse import context


class TestBasicFunctions(unittest.TestCase):

    def setUp(self):
        pass

    def test_closestFloorValue(self):
        lst = numpy.asarray(range(0, 100, 10))
        self.assertEquals(utils.closestFloorValue(41, lst), (40, 4))
        self.assertEquals(utils.closestFloorValue(40, lst), (40, 4))
        with self.assertRaises(ValueError):
            utils.closestFloorValue(-1, lst)

        ctx = context.get_context('test/src/test-ctypes3.32.dump')
        lst = ctx._structures_addresses
        # print ['0x%0.8x'%i for i in lst]

if __name__ == '__main__':
    unittest.main(verbosity=0)
