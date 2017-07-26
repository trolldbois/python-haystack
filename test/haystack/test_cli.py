#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import unittest

from haystack import cli
from test.haystack import SrcTests

from contextlib import contextmanager
try:
    from StringIO import StringIO
except:
    from io import StringIO
try:
    from unittest import mock
except ImportError:
    import mock


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestCLI(SrcTests):

    @classmethod
    def setUpClass(cls):
        cls.dumpname = 'dmp://./test/dumps/minidump/cmd.dmp'
        cls.cache_dumpname = cls.dumpname[8:]+'.d'
        # config.remove_cache_folder(cls.cache_dumpname)

    @unittest.skip('argparse kills the run')
    def test_cli_usage(self):
        # check the helper desc
        # use buffered mode
        args = ['haystack-search', '--help']
        sys.argv = args
        with captured_output() as (out, err):
            cli.search()
        # This can go inside or outside the `with` block
        output = out.getvalue().strip()
        self.assertIn(output, 'dir://')
        self.assertIn(output, 'dmp://')
        self.assertIn(output, 'volatility://')
        self.assertIn(output, 'rekall://')
        self.assertIn(output, 'live://')

        # self.assertIn('0x000d0000', ret)

        return

    def test_show(self):
        testargs = ["haystack-show", self.dumpname, 'test.structures.stringarray.array_of_pointers', '0x543108']
        with mock.patch.object(sys, 'argv', testargs):
            # no exception
            cli.show()

        return


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
