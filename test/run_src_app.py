#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Launch our test unit applications."""

import logging
import os
import subprocess
import sys

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


TESTS = {"test1": "test-ctypes1",
         "test2": "test-ctypes2",
         "test3": "test-ctypes3",
         }


def run_app_test(testName, stdout=sys.stdout):
    if testName not in TESTS:
        raise ValueError("damn, please choose testName in %s" % (TESTS.keys()))
    appname = TESTS[testName]
    srcDir = os.path.sep.join([os.getcwd(), 'test', 'src'])
    tgt = os.path.sep.join([srcDir, appname])
    if not os.access(tgt, os.F_OK):
        print('\nCould not find test binaries', tgt)
        print('HAVE YOU BUILD THEM ?')
        raise IOError
    return subprocess.Popen([tgt], stdout=stdout)


def makeTests():
    os.getcwd()
    makeCmd = ['make','-d']
    p = subprocess.Popen(makeCmd, stdout=sys.stdout, cwd='test/src/')
    p.wait()
