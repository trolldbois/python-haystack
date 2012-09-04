#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import os
import array
import struct
import itertools

from haystack.config import Config
from haystack.utils import unpackWord
from haystack.reverse import re_string, fieldtypes
from haystack.reverse.fieldtypes import FieldType, Field
from haystack.reverse.heuristics.model import FieldAnalyser, StructureAnalyser

import ctypes

log = logging.getLogger('dsa')

## Field analysis related functions and classes

class ZeroFields(FieldAnalyser):
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
    bytes = structure.bytes
    assert( (vaddr+offset)%Config.WORDSIZE == 0 )
    #aligned_off = (vaddr+offset)%Config.WORDSIZE 
    #start = (vaddr+offset)
    #if aligned_off != 0: # align to next
    #  start += (Config.WORDSIZE - aligned_off)
    #  size  -= (Config.WORDSIZE - aligned_off)
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
    collates = list()
    prev = matches[0]-1
    x = []
    # PERF TODO: whats is algo here
    for i in matches:
      if i-1 == prev:
        x.append(i)
      else:
        collates.append(x)
        x = []
    collates.append(x)
    # we now have collated, lets create fields
    for field in collates:
      flen = len(field)
      if flen > 1:
        size = Config.WORDSIZE * flen
      elif flen == 1:
        size = Config.WORDSIZE
      else:
        continue
      # make a field
      start = field[0]
      fields.append( Field(structure, start, self._typename, size, False) ) 
    # we have all fields
    return fields

class StringFields(FieldAnalyser):
  ''' rfinds utf-16-ascii and ascii 7bit
  
  '''
  def make_fields(self, structure, offset, size):
    ''' try to find a utf-16 string starting from end.'''
    bytes = structure.bytes
    index = re_string.rfind_utf16(bytes, offset, size)
    if index > -1:
      f = Field(structure, offset+index, FieldType.STRING, size-index, False)  
      return f
    return False

  #def _utf16(self, )


class PointerFields(FieldAnalyser):
  
  def make_fields(self, structure, offset, size):
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


class IntegerArrayFields(FieldAnalyser):
  def make_fields(self, structure, offset, size):
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
        

class IntegerFields(FieldAnalyser):
  def make_fields(self, structure, offset, size):
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

    

