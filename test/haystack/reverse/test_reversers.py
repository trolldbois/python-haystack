#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import os
import sys
import unittest

from haystack import config
Config = config.make_config_linux_32() # forcing it on these unittest

from haystack import model
from haystack.reverse import context
from haystack.reverse import reversers
from haystack.reverse.heuristics.dsa import *

import ctypes 

class TestStructureSizes(unittest.TestCase):

  @classmethod
  def setUpClass(cls):    
    sys.path.append('test/src/')
    import ctypes3
    
    node = ctypes3.struct_Node
    node._expectedValues_ = dict([('val1',[0xdeadbeef]),('ptr2',[model.NotNull])])
    test3 = ctypes3.test3
    test3._expectedValues_ = dict([
      ('val1', [0xdeadbeef]),
      ('val1b', [0xdeadbeef]),
      ('val2', [0x10101010]),
      ('val2b', [0x10101010]),
      ('me',[model.NotNull]) ])
    cls.dsa = DSASimple()


  def setUp(self):    
    #os.chdir()
    self.context = context.get_context('test/src/test-ctypes3.dump')

  def tearDown(self):
    self.context = None

  def test_sizes(self):
    structs = self.context.listStructures()
    sizes = list(set([ len(s) for s in structs]))
    sizes.sort() # Node and test3
    import ctypes3
    for st in structs: #[1:2]:
      self.dsa.analyze_fields(st)
      #print st.toString()
      #print repr(self.context.heap.readBytes(st._vaddr, len(st)))

    # there are only two struct types
    # the free chunks is not listed
    self.assertEqual( len(sizes), 2) 
    self.assertEqual( len(structs), 6) 
    
    #st = ctypes3.Node()
    #print st.toString(), st._expectedValues_

    #print ctypes3.test3.__dict__
    #print ctypes3.Node.__dict__
    #print 'test3',ctypes.sizeof(ctypes3.test3)
    #if ctypes.sizeof(ctypes3.test3) % Config.get_word_size() == 0:
    #  print 'MOD'
    self.assertEqual( sizes[1], ctypes.sizeof(ctypes3.test3))
    
    # is that padding I see ?
    self.assertNotEqual( sizes[0], ctypes.sizeof(ctypes3.struct_Node), 'There should be a 4 bytes padding here')
    self.assertEqual( sizes[0]-4, ctypes.sizeof(ctypes3.struct_Node), 'There should be a 4 bytes padding here')
    #print 'Node', ctypes.sizeof(ctypes3.Node)
    #if ctypes.sizeof(ctypes3.Node) % Config.get_word_size() == 0:
    #  print 'MOD'


class TestFullReverse(unittest.TestCase):
    
  def test_reverseInstances(self):
    ctx = context.get_context('test/dumps/ssh/ssh.1')
    dumpname = 'test/dumps/ssh/ssh.1'
    ctx = Config.cleanCache(dumpname)
    ctx = reversers.reverseInstances(dumpname)



if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  unittest.main()

