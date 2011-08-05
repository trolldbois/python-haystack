#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, os, pickle, time, sys
import struct
import ctypes

from haystack import memory_dumper

log = logging.getLogger('signature')


''' 
see bsdiff python-bsdiff 
see cmp --list
'''

class FeedbackGiver:
  def _initSteps(self, _len, steps=10):
    pass
  
  def _checkSteps(self):
    pass
  
  def feedback(self, step, val):
    ''' make a feedback'''
    #log.info('processing offset 0x%x'%(val))
    pass

class AbstractSearcher(FeedbackGiver):
  ''' Search for something in memspace. '''
  WORDSIZE = ctypes.sizeof(ctypes.c_void_p) # config
  def __init__(self, mapping):
    self.mapping = mapping
    self._initSteps(len(self.mapping))

  def _initSteps(self, _len, steps=10):
    ''' calculate the offsets at which feedback would be given '''
    self.steps = [o for o in range(0,_len, _len/steps)] # py 3 compatible
    return
  
  def _checkSteps(self, step):
    if len(self.steps) == 0:
      return
    if step > self.steps[0]:
      val = self.steps.pop(0)
      self.feedback(step, val)
    return

  def search(self):
    ''' find all valid matches offsets in the memory space '''
    self.values = set()
    log.debug('search %s mapping for matching values'%(self.mapping))
    for offset in xrange(0,len(self.mapping), self.WORDSIZE):
      self._checkSteps(offset) # be verbose
      if self.testMatch(offset):
        self.values.add(offset)
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    log.debug('iterate %s mapping for matching values'%(self.mapping))
    for offset in xrange(0,len(self.mapping), self.WORDSIZE):
      self._checkSteps(offset) # be verbose
      if self.testMatch(offset):
        yield offset
    return 

  def testMatch(self, offset):
    ''' implement this methods to test for a match at that offset '''
    raise NotImplementedError

class PointerSearcher(AbstractSearcher):
  ''' 
  Search for pointers by checking if the word value is a valid addresses in memspace.
  '''
  def testMatch(self, offset):
    vaddr = offset + self.mapping.start
    word = self.mapping.readWord(vaddr)
    if word in self.mapping:
      return True
    return False

class NullSearcher(AbstractSearcher):
  ''' 
  Search for Nulls words in memspace.
  '''
  def testMatch(self,offset):
    vaddr = offset + self.mapping.start
    word = self.mapping.readWord(vaddr)
    if word == 0:
      return True
    return False

class SignatureMaker(AbstractSearcher):
  ''' 
  make a condensed signature of the mapping. 
  We could then search the signature file for a specific signature
  '''
  
  NULL = 0x1
  POINTER = 0x2 
  #POINTERS = NULL | POINTER # null can be a pointer value so we can byte-test that
  OTHER = 0x4

  def __init__(self, mapping):
    AbstractSearcher.__init__(self,mapping)
    self.pSearch = PointerSearcher(self.mapping) 
    self.nSearch = NullSearcher(self.mapping) 
    
  def testMatch(self,offset):
    ''' return either NULL, POINTER or OTHER '''
    if self.nSearch.testMatch(offset):
      return self.NULL
    if self.pSearch.testMatch(offset):
      return self.POINTER
    return self.OTHER

  def search(self):
    ''' returns the memspace signature. Dont forget to del that object, it's big. '''
    self.values = b''
    log.debug('search %s mapping for matching values'%(self.mapping))
    for offset in xrange(0,len(self.mapping), self.WORDSIZE):
      self._checkSteps(offset) # be verbose
      self.values += struct.pack('B',self.testMatch(offset))
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to return the signature of that memspace '''
    log.debug('iterate %s mapping for matching values'%(self.mapping))
    for offset in xrange(0,len(self.mapping), self.WORDSIZE):
      self._checkSteps(offset) # be verbose
      yield struct.pack('B',self.testMatch(offset))
    return 
  

def _openDumpfile(dumpfile):
  # load memorymapping
  mappings = memory_dumper.load(dumpfile)
  # TODO : make a mapping chooser 
  if len(mappings) > 1:
    heap = [m for m in mappings if m.pathname == '[heap]'][0]
  else:
    heap = mappings[0]
  return heap

def toFile(dumpFile, outputFile):
  log.info('Loading the mappings in the memory dump file.')
  mapping = _openDumpfile(dumpFile)
  log.info('Make the signature.')
  sigMaker = SignatureMaker(mapping)
  sig = sigMaker.search()
  outputFile.write(sig)
  log.info('Signature written to %s.'%(outputFile.name))
  del sig
  del sigMaker
  return

def makesig(opt):
  toFile(opt.dumpfile, opt.sigfile)
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-sig', description='Make a heap signature.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  rootparser.add_argument('sigfile', type=argparse.FileType('wb'), action='store', help='The output signature filename.')
  rootparser.set_defaults(func=makesig)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('ctypes_openssh').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('gui').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
