# -*- coding: utf-8 -*-

"""Tests haystack.abouchet on Windows memory dump ."""

import logging
import unittest

if __name__ == '__main__':
    import sys
    logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
    #logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.getLogger('basicmodel').setLevel(level=logging.DEBUG)
    # logging.getLogger('model').setLevel(level=logging.DEBUG)
    # logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
    unittest.main(verbosity=2)
