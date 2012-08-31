#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import os
import collections
import struct
import itertools

from haystack.config import Config
from haystack.utils import unpackWord
from haystack.reverse import re_string, fieldtypes
from haystack.reverse.heuristics.model import FieldAnalyzer, StructureAnalyzer

import ctypes

log = logging.getLogger('dsa')

## Field analysis related functions and classes

class ZeroFields(FieldAnalyzer):
  ''' checks for possible fields, aligned, with WORDSIZE zeros.'''
  def make_fields(self, structure, offset, size):
    self._typename = FieldType.ZEROES
    self._zeroes = '\x00'*Config.WORDSIZE
    
    ret = self._find_zeroes(structure, offset, size)
    
    # TODO if its just a word, we should say its a small int.
    return ret  
  
  def _find_zeroes(self, structure, offset, size):
    ''' iterate over the bytes until a byte if not \x00 
    '''
    vaddr = structure._vaddr
    bytes = structure.bytes()
    aligned_off = (vaddr+offset)%Config.WORDSIZE 
    start = (vaddr+offset)
    if aligned_off != 0: # align to next
      start += (Config.WORDSIZE - aligned_off)
      size  -= (Config.WORDSIZE - aligned_off)
    # iterate
    matches = array.array('i')
    for i in range(start, start+size, Config.WORDSIZE ):
      # PERF TODO: bytes or struct test ?
      if bytes[start:start+Config.WORDSIZE] == self._zeroes:
        matches.append(start)
    # collate
    if len(matches) == 0:
      return False
    # lets try to get fields
    fields = []
    # first we need to collate neighbors
    collates = set()
    prev = matches[0]-1
    x = []
    # PERF TODO: whats is algo here
    for i in matches:
      if i-1 == prev:
        x.append(i)
      else:
        collates.add(x)
        x = []
    collates.add(x)
    # we now have collated, lets create fields
    for field in collates:
      flen = len(field)
      if flen > 1:
        size = Config.WORDSIZE * flen
      elif flen == 1:
        size = 1
      else:
        continue
      # make a field
      fields.append( Field(structure, start+field, self._typename, size, False) ) 
    # we have all fields
    return fields

class StringFields(FieldAnalyzer):
  
  def make_fields(self, bytes, offset, size):
    ''' if there is no \x00 termination, its not a string
    that means that if we have a bad pointer in the middle of a string, 
    the first part will not be understood as a string'''
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    ret = re_string.try_decode_string(bytes)
    if not ret:
      self.typesTested.append(FieldType.STRING)
      #log.warning('STRING: This is not a string %s'%(self))
      return False
    else:
      self.size, self.encoding, self.value = ret 
      # FieldType.STRING or NULLTERMINATEDSTRING
      self.typename = FieldType.STRING
      if self.value[-1] == '\x00':
        self.typename = FieldType.STRINGNULL
      log.debug('STRING: Found a string "%s"/%d for encoding %s, field %s'%( repr(self.value), self.size, self.encoding, self))
      return True


class PointerFields(FieldAnalyzer):
  
  def make_fields(self, bytes, offset, size):
    if (self.offset%Config.WORDSIZE != 0):
      return False
    bytes = self.struct.bytes[self.offset:self.offset+Config.WORDSIZE]
    if len(bytes) != Config.WORDSIZE:
      return False      
    value = unpackWord(bytes)[0] #TODO biteorder
    # TODO check if pointer value is in range of mappings and set self.comment to pathname value of pointer
    if value in self.struct._mappings:
      log.debug('checkPointer offset:%s value:%s'%(self.offset, hex(value)))
      self.value = value
      self.size = Config.WORDSIZE
      # TODO: leverage the context._function_names 
      if self.value in self.struct._context._function_names :
        self.comment = ' %s::%s'%(os.path.basename(self.struct._mappings.getMmapForAddr(self.value).pathname), 
                    self.struct._context._function_names[self.value])
      else:
        self.comment = self.struct._mappings.getMmapForAddr(self.value).pathname 
      self.typename = FieldType.POINTER
      return True
    else:
      return False


  def checkIntegerArray(self):
    # this should be last resort
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < 4:
      return False
    ctr = collections.Counter([ bytes[i:i+Config.WORDSIZE] for i in range(len(bytes)) ] )
    floor = max(1,int(size*.1)) # 10 % variation in values
    #commons = [ c for c,nb in ctr.most_common() if nb > 2 ]
    commons = ctr.most_common()
    if len(commons) > floor:
      return False # too many different values
    # few values. it migth be an array
    self.size = size
    self.values = bytes
    self.comment = '10%% var in values: %s'%(','.join([ repr(v) for v,nb in commons]))
    return True
        
  def checkArrayCharP(self):
    pass
    
  def checkInteger(self):
    log.debug('checking Integer')
    if (self.struct._vaddr+self.offset) % Config.WORDSIZE != 0:
      # TODO  txt[:11] + 0 + int for alignement
      # non aligned int is not an int
      #print 'OUT noon aligned'
      return False
    if self.checkSmallInt():
      return True
    elif self.checkSmallInt(endianess='>'):
      return True
    elif self.size == Config.WORDSIZE:
      bytes = self.struct.bytes[self.offset:self.offset+self.size]
      self.value = unpackWord(bytes[:Config.WORDSIZE], '@')[0] 
      self.typename = FieldType.INTEGER
      self.endianess = '@' # unknown
      return True
    return False

  def checkSmallInt(self, endianess='<'):
    # TODO
    bytes = self.struct.bytes[self.offset:self.offset+self.size]
    size = len(bytes)
    if size < Config.WORDSIZE:
      return False
    val = unpackWord(bytes[:Config.WORDSIZE], endianess)[0] 
    if val < 0xffff:
      self.value = val
      self.size = Config.WORDSIZE
      self.typename = FieldType.SMALLINT
      self.endianess = endianess
      return True
    elif ( (2**(Config.WORDSIZE*8) - 0xffff) < val): # check signed int
      self.value = val
      self.size = Config.WORDSIZE
      self.typename = FieldType.SIGNED_SMALLINT
      self.endianess = endianess
      return True
    return False

    

