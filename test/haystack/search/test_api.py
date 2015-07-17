#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest


class TestAPI(unittest.TestCase):

    def test_all(self):
        import haystack
        memdumpname = '../test/src/test-ctypes3.64.dump'
        # we need a memory dump loader
        from haystack import dump_loader
        memory_handler = dump_loader.load(memdumpname)
        print memory_handler

        # we need to add our test path to the env
        import sys
        sys.path.append('../test/src/')
        py_modulename = 'ctypes3_gen64'

        # load this module with haystack
        my_model = memory_handler.get_model()
        test3 = my_model.import_module( py_modulename )
        print test3.__dict__.keys()

        py_class = test3.struct_Node
        results = haystack.search_record(memory_handler, py_class)
        print results

        out = haystack.output_to_string(memory_handler, results)
        print out

        out = haystack.output_to_python(memory_handler, results)
        print out

        from haystack import constraints
        handler = constraints.ConstraintsConfigHandler()

        my_constraints = handler.read('../test/src/ctypes3.constraints')



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # logging.basicConfig(level=logging.INFO)
    unittest.main(verbosity=2)
