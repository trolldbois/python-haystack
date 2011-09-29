#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module holds some basic utils function.
'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os
import array
import encodings
import logging

log = logging.getLogger('re_string')

_py_encodings = set(encodings.aliases.aliases.values())


def startsWithString(bytesarray):
  ''' if there is no \x00 termination, its not a string
  that means that if we have a bad pointer in the middle of a string, 
  the first part will not be understood as a string'''
  bytes = self.struct.bytes[self.offset:]
  i = bytes.find('\x00')
  if i == -1:
    self.typename = None
    self.typesTested.append(Field.STRING)
    return False
  else:
    log.debug('Probably Found a string type')
    self.size = i
    chars = bytes[:i]
    notPrintable = []
    for i,c in enumerate(chars):
      if c not in string.printable:
        notPrintable.append( (i,c) )
    if len(notPrintable)>0:
      log.debug('Not a string, %d/%d non printable characters'%( len(notPrintable), i ))
      self.typename = None
      self.typesTested.append(Field.STRING)
      self.size = None
      return False
    else:
      log.debug('Found a string "%s"'%(chars))
      if len(chars) == 1: # try unicode
        log.debug('Unicode test on %s: %s'%(self.struct.name(), repr(bytes)) )
        
      return True


def testAllEncodings(bytearray):
  res = []
  for codec in _py_encodings:
    length, my_str = testEncoding(bytesarray, codec)
    if length != -1:
      res.append( (length, codec, my_str) )
  res.sort(reverse=True)
  return res
  
def testUTF8(bytesarray):
  return testEncoding(bytesarray, 'UTF-8')
def testUTF16(bytesarray):
  return testEncoding(bytesarray, 'UTF-16')
def testUTF32(bytesarray):
  return testEncoding(bytesarray, 'UTF-32')

def testEncoding(bytesarray, encoding):
  ''' test for null bytes on even bytes'''
  try:
    ustr = bytesarray.decode(encoding)
  except UnicodeDecodeError:
    return -1, None
  i = ustr.find('\x00')
  if i == -1:
    return -1, None
  else:
    return i, ustr[:i]
    
  even = [ c for i,c in enumerate(bytesarray]

