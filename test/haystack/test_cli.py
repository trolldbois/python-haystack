#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.basicmodel ."""

import logging
import unittest

import os
import subprocess
import sys
from haystack import cli
from test.haystack import SrcTests


class TestCLI(SrcTests):

    def test_find_heap(self):
        p = os.path.sep.join([os.getcwd(), 'scripts'])
        sys.path.append(p)
        cmd = 'python scripts/haystack-find-heap.py -v test/dumps/minidump/alg.dmp'.split(" ")
        args=['scripts/haystack-find-heap.py']
        ret = subprocess.check_output(cmd)
        self.assertIn('0x000d0000', ret)
        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
