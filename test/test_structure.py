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
#from haystack.reverse.utils import SharedBytes
SharedBytes=str

class TestStructure(unittest.TestCase):

  def asetUp(self):
    self.s1 = pickle.load(file('AnonymousStruct_84_ad35de0','r') )
    self.s1_bytes = SharedBytes(file('AnonymousStruct_84_ad35de0.bytes','r').read())
    self.s2 = pickle.load(file('AnonymousStruct_130256_ad39240','r') )
    self.s2_bytes = SharedBytes(file('AnonymousStruct_130256_ad39240.bytes','r').read())
    self.s2 = structure.AnonymousStructInstance(self.s2.mappings, 0, self.s2_bytes)
  
  #
  '''
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
  '''
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
    file('%s.agg'%(self.s2),'w').write( self.s2.toString() )

    l1 = -1
    l2 = -2
    i = 0
    ''' loop until there is not array xtraction to be made '''
    while l1 != l2:
      self.s2._excludeSizeVariableFromIntArray()
      file('%s.exclude.run%d'%(self.s2,i),'w').write( self.s2.toString() )
      l1 = len(self.s2.fields)
      
      self.s2._aggZeroesBetweenIntArrays()
      file('%s.IZItoIntArray.run%d'%(self.s2,i),'w').write( self.s2.toString() )
      l2 = len(self.s2.fields)
      i+=1

    #logging.getLogger('structure').setLevel(logging.DEBUG)
    #self.s2._findSubStructures()
    #file('%s.findsub'%(self.s2),'w').write( self.s2.toString() )
    #self.s2.save()

    self.s2._aggregateFields()
    file('%s.agg.post'%(self.s2),'w').write( self.s2.toString() )
    
    #self.s2._checkZeroesIndexes()
    #file('%s.ZeroesIndexes'%(self.s2),'w').write( self.s2.toString() )
    
    logging.getLogger('structure').setLevel(logging.DEBUG)
    self.s2._checkBufferLen()
    file('%s.checkBufLen'%(self.s2),'w').write( self.s2.toString() )

    self.s2.save()
    # field 0 untyped 
    return  

  '''
from haystack.reverse import structure
from  structure import *
import logging
logging.basicConfig(level=logging.DEBUG)
import pickle
s2 = pickle.load(file('AnonymousStruct_130256_0'))

f0=s2.fields[0]
f0.decoded=False
f0.typename = fieldtypes.FieldType.UNKNOWN
f0.decodeType()

s=512
source = s2.bytes[:s*4] # first field size is probably a 2**12
# not. 512 really
ha = []
hb = []
ints = [i for i in struct.unpack('L'*(len(source)/4), source)]
groups = [ (ints[i:i+4], ints[i+4:i+8]) for i in range(0,len(ints),8)]
for a,b in groups:
  ha.extend(a)
  hb.extend(b)

has=sorted(ha)
iA = [has[i+1]-has[i] for i in range(len(has)-1)]
iiA = [iA[i]-iA[i+1] for i in range(len(iA)-1)]
iiiA = [iiA[i]-iiA[i+1] for i in range(len(iiA)-1)]

mid = has[len(has)/2]
var = [ v-mid for v in ha]



'''  
  ''' 
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
  '''



if __name__ == '__main__':
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
