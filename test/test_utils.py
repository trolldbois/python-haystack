#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import struct
import operator
import os
import unittest

from haystack import memory_mapping
from haystack.config import Config
from haystack.model import *
from haystack.utils import *


class St(ctypes.Structure):
  _fields_ = [ ('a',ctypes.c_int) ]

#
btype = ctypes.c_int(2)
voidp = ctypes.c_void_p(2)
st = St()
stp = ctypes.pointer(st)
arra1 = (ctypes.c_long *4)()
arra2 = (St *4)()
arra3 = (ctypes.POINTER(St) *4)()
string = ctypes.c_char_p()
fptr = ctypes.memmove
arra4 = (type(fptr)*256)()


class TestBasicFunctions(unittest.TestCase):

  def setUp(self):
    self.tests = set([btype, voidp, st, stp, arra1, arra2, arra3, string, fptr, arra4])
  
  def test_isBasicType(self):
    valids = set([btype])
    invalids = self.tests - valids
    self.assertTrue( utils.isBasicType( valid ))
    
    for var in invalids:
      self.assertFalse( utils.isBasicType( var ))


if __name__ == '__main__':
    unittest.main()

def test_import():
  ''' replace c_char_p '''
  if ctypes.c_char_p.__name__ == 'c_char_p':
    print('c_char_p is not our CString')
    return False

  ''' keep orig class '''
  if ctypes.Structure.__name__ == 'Structure':
    print('Structure is not our LoadablesMembers')
    return False
  return True

def test_array2bytes():
  return True

def test_bytes2array():
  return True

def test_pointer2bytes():
  return True




def test_isBasicType():
  ret = ( isBasicType(btype) and not isBasicType(st) and not isBasicType(string) 
    and not isBasicType(arra1)
    and not isBasicType(arra2)
    and not isBasicType(arra3)
    and not isBasicType(arra4)
  ) 
  return ret

def test_isStructType():
  return isStructType(st)
  
def test_isPointerType():
  return isPointerType(stp) and not isPointerType(fptr) and isPointerType(voidp)

def test_isBasicTypeArrayType():
  ret = ( not isBasicTypeArrayType(btype) and not isBasicTypeArrayType(st) and not isBasicTypeArrayType(string) 
    and isBasicTypeArrayType(arra1)
    and not isBasicTypeArrayType(arra2)
    and not isBasicTypeArrayType(arra3)
    and not isBasicTypeArrayType(arra4)
  ) 
  return ret

def test_isArrayType():
  ret = ( not isArrayType(btype) and not isArrayType(st) and not isArrayType(string) 
    and isArrayType(arra1)
    and isArrayType(arra2)
    and isArrayType(arra3)
    and isArrayType(arra4)
  ) 
  return ret

def test_isFunctionType():
  return isFunctionType(fptr) and not isFunctionType(stp) and isFunctionType(arra4[0])

def test_isCStringPointer():
  return isCStringPointer(string)

def test_isUnionType():
  return True

def testAll():
  return ( test_import()
  and test_array2bytes()
  and test_bytes2array()
  and test_pointer2bytes()
  and test_isBasicType()
  and test_isStructType()
  and test_isPointerType()
  and test_isBasicTypeArrayType()
  and test_isArrayType()
  and test_isFunctionType()
  and test_isCStringPointer()
  and test_isUnionType()
  )


