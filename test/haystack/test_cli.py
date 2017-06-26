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


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
