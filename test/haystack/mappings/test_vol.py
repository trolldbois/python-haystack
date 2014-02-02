#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import unittest
import logging

from haystack import model
from haystack.mappings.vol import VolatilityProcessMapper
from haystack.mappings.vol import VolatilityProcessMapping

log = logging.getLogger('test_vol')


class TestMapper(unittest.TestCase):
    def setUp(self):    
        model.reset()

    def test_init(self):
        f = '/home/jal/outputs/vol/zeus.vmem'
        pid = 676 # services
        #pid = 124 #cmd
        mapper = VolatilityProcessMapper(f,pid)
        print 'mapper initialised'
        #import code
        #code.interact(local=locals())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    #logging.basicConfig(level=logging.INFO)
    #logging.getLogger('memory_mapping').setLevel(logging.DEBUG)
    #logging.getLogger('basicmodel').setLevel(logging.INFO)
    #logging.getLogger('model').setLevel(logging.INFO)
    #logging.getLogger('listmodel').setLevel(logging.INFO)
    unittest.main(verbosity=2)


