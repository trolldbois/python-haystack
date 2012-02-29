#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os
import sys
import unittest

from haystack import model
from haystack.reverse import reversers

sys.path.append('test/src/')
import ctypes3

import ctypes 

class TestStructureSizes(unittest.TestCase):

  @classmethod
  def setUpClass(cls):    
    node = ctypes3.Node
    node._expectedValues_ = dict([('val1',[0xdeadbeef]),('ptr2',[model.NotNull])])
    test3 = ctypes3.test3
    test3._expectedValues_ = dict([
      ('val1', [0xdeadbeef]),
      ('val1b', [0xdeadbeef]),
      ('val2', [0x10101010]),
      ('val2b', [0x10101010]),
      ('me',[model.NotNull]) ])

  def setUp(self):    
    #os.chdir()
    self.context = reversers.getContext('test/src/test-ctypes3.dump')

  def test_sizes(self):
    structs = self.context.listStructures()
    sizes = list(set([ len(s) for s in structs]))
    sizes.sort()
    import ctypes3
    self.assertEqual( len(sizes), 2)
    for st in structs: #[1:2]:
      st.decodeFields()
      #print st.toString()
      #print repr(self.context.heap.readBytes(st._vaddr, len(st)))

    #st = ctypes3.Node()
    #print st.toString(), st._expectedValues_

    #print ctypes3.test3.__dict__
    #print ctypes3.Node.__dict__
    #print ctypes.sizeof(ctypes3.Node)
    self.assertEqual( sizes[1], ctypes.sizeof(ctypes3.test3))
    
    # is that padding I see ?
    self.assertEqual( sizes[0], ctypes.sizeof(ctypes3.Node))




if __name__ == '__main__':
    unittest.main()

