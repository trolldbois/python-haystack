#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import sys
import unittest

from haystack import cliwin
from test.haystack import SrcTests


class TestCLI(SrcTests):

    def test_find_heap(self):
        # haystack-find-heap
        args = ['haystack-find-heap', '-v', 'test/dumps/minidump/alg.dmp']
        sys.argv = args
        cliwin.find_heap()
        # self.assertIn('0x000d0000', ret)
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
