#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import struct
import operator
import os
import unittest
import pickle
import sys

from haystack.config import Config
#from haystack.reverse import structure
#import haystack.reverse.structure as structure
sys.path.append('../haystack/reverse/')
import structure

class TestStructure(unittest.TestCase):

  def asetUp(self):
    self.s1 = pickle.load(file('AnonymousStruct_84_ad35de0','r') )
    self.s1_bytes = file('AnonymousStruct_84_ad35de0.bytes','r').read()
    self.s2 = pickle.load(file('AnonymousStruct_130256_ad39240','r') )
    self.s2_bytes = file('AnonymousStruct_130256_ad39240.bytes','r').read()
    self.s2 = structure.AnonymousStructInstance(self.s2.mappings, 0, self.s2_bytes)
  
  def test_guessField(self):
    self.assertEqual( None, None)
    return  

  def test_decodeFields(self):
    #self.s2.decodeFields()
    #print self.s2.toString()
    return  

  def test_aggregateZeroes(self):
    return  
    
  def test_fixGaps(self):
    return  
  
  def test_fixOverlaps(self):
    return  
  
  def test_getOverlapping(self):
    return  
  
  def test_resolvePointers(self):
    return  
  
  def test_resolvePointerToStructField(self):
    return  
  
  def test_aggregateFields(self):
    self.asetUp()
    logging.basicConfig(level=logging.INFO)
    #logging.getLogger('pattern').setLevel(logging.DEBUG)
    #print self.s2.fields
    #print 'resolved:',self.s2.resolved
    #print 'pointerResolved:',self.s2.pointerResolved
    for f in self.s2.fields:
      f.decodeType()
    self.s2.decodeFields()
    file('%s.before'%(self.s2),'w').write( self.s2.toString() )
    self.s2.pointerResolved=True
    self.s2._aggregateFields()
    file('%s.after'%(self.s2),'w').write( self.s2.toString() )
    
    logging.getLogger('structure').setLevel(logging.DEBUG)
    self.s2._findSubStructures()
    file('%s.after.sub'%(self.s2),'w').write( self.s2.toString() )
    return  
      
  def test_isPointerToString(self):
    return  
    
  
  def test_getPointerFields(self):
    return  
    
  def test_getSignature(self):
    return  
  
  def test_toString(self):
    return  

  def test_contains(self):
    return  
      
  def test_getitem(self):
    return  
    
  def test_len(self):
    return  

  def test_cmp(self):
    return  
  
  def test_str(self):
    return 




if __name__ == '__main__':
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
