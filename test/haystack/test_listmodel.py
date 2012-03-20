#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.listmodel ."""

import logging
import unittest

from haystack import dump_loader
from haystack.config import Config
from haystack import model
from haystack import utils
from haystack.reverse.win32 import win7heap


__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"




class TestListStruct(unittest.TestCase):
  '''
  haystack --dumpname putty.1.dump --string haystack.reverse.win32.win7heap.HEAP refresh 0x390000
  '''

  def setUp(self):
    offset = 0x390000
    self.mappings = dump_loader.load('putty.1.dump')
    self.m = self.mappings.getMmapForAddr(offset)
    self.heap = self.m.readStruct(offset, win7heap.HEAP)
  
  def test_iter(self):
    self.assertTrue(self.heap.loadMembers(self.mappings, 10 ))
    
    for el in self.heap.UCRList.iterateList(self.mappings):
      print el
    return 




if __name__ == '__main__':
  unittest.main(verbosity=2)
  logging.setLogger(listmodel, level=logging.DEBUG)  

