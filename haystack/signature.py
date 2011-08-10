#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, os, pickle, time, sys
import re
import struct
import ctypes

from haystack import memory_dumper

log = logging.getLogger('signature')


''' 
see bsdiff python-bsdiff 
see cmp --list
'''

py_xrange=xrange

def xrange(start, end, step):
  ''' stoupid int xrange... '''
  end=end-start
  for val in py_xrange(0, end, step):
    yield start+val
  return
  
class FeedbackGiver:
  def _initSteps(self, _len, steps=10):
    pass
  
  def _checkSteps(self):
    pass
  
  def feedback(self, step, val):
    ''' make a feedback'''
    #log.info('processing vaddr 0x%x'%(val))
    pass

class AbstractSearcher(FeedbackGiver):
  ''' Search for something in memspace. 
    feedback(step, val) will be called each step  
  '''
  WORDSIZE = ctypes.sizeof(ctypes.c_void_p) # config
  def __init__(self, mapping, steps=10, feedback=None):
    self.mapping = mapping
    self._initSteps(self.mapping.start, self.mapping.end, steps)

  def _initSteps(self, start, end, steps):
    ''' calculate the vaddr at which feedback would be given '''
    self.steps = [o for o in range(start,end, (end-start)/steps)] # py 3 compatible
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
    for vaddr in xrange(self.mapping.start, self.mapping.end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      if self.testMatch(vaddr):
        self.values.add(vaddr)
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    log.debug('iterate %s mapping for matching values'%(self.mapping))
    for vaddr in xrange(self.mapping.start, self.mapping.end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      if self.testMatch(vaddr):
        yield vaddr
    return 

  def testMatch(self, vaddr):
    ''' implement this methods to test for a match at that offset '''
    raise NotImplementedError

class PointerSearcher(AbstractSearcher):
  ''' 
  Search for pointers by checking if the word value is a valid addresses in memspace.
  '''
  def testMatch(self, vaddr):
    word = self.mapping.readWord(vaddr)
    if word in self.mapping:
      return True
    return False

class NullSearcher(AbstractSearcher):
  ''' 
  Search for Nulls words in memspace.
  '''
  def testMatch(self, vaddr):
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
    
  def testMatch(self, vaddr):
    ''' return either NULL, POINTER or OTHER '''
    if self.nSearch.testMatch(vaddr):
      return self.NULL
    if self.pSearch.testMatch(vaddr):
      return self.POINTER
    return self.OTHER

  def search(self):
    ''' returns the memspace signature. Dont forget to del that object, it's big. '''
    self.values = b''
    log.debug('search %s mapping for matching values'%(self.mapping))
    for vaddr in xrange(self.mapping.start, self.mapping.end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      self.values += struct.pack('B', self.testMatch(vaddr))
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to return the signature of that memspace '''
    log.debug('iterate %s mapping for matching values'%(self.mapping))
    for vaddr in xrange(self.mapping.start, self.mapping.end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      yield struct.pack('B',self.testMatch(vaddr))
    return 



class RegexpSearcher(AbstractSearcher):
  ''' 
  Search by regular expression in memspace.
  '''
  def __init__(self, mapping, regexp):
    AbstractSearcher.__init__(self,mapping)
    self.regexp = regexp
    self.pattern = re.compile(regexp, re.IGNORECASE)

  def search(self):
    ''' find all valid matches offsets in the memory space '''
    self.values = set()
    log.debug('search %s mapping for matching values %s'%(self.mapping, self.regexp))
    for match in self.pattern.finditer(self.mapping.mmap()):
      offset = match.start()
      if type(value) == list :
        value = ''.join([chr(x) for x in match.group()])
      vaddr = offset+self.mapping.start
      self._checkSteps(vaddr) # be verbose
      self.values.add((vaddr,value) )
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    log.debug('iterate %s mapping for matching values'%(self.mapping))
    for match in self.pattern.finditer(self.mapping.mmap()):
      offset = match.start()
      value = match.group(0) # [] of int ?
      if type(value) == list :
        value = ''.join([chr(x) for x in match.group()])
      vaddr = offset+self.mapping.start
      self._checkSteps(vaddr) # be verbose
      yield (vaddr,value) 
    return 

  def testMatch(self, vaddr):
    return True

EmailRegexp = r'[a-zA-Z0-9+_\-\.]+@[0-9a-zA-Z][.-0-9a-zA-Z]*.[a-zA-Z]+' 
URLRegexp = r'[a-zA-Z0-9]+://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+' 
IPv4Regexp = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}' 

'''
lib["email"] = re.compile(r"(?:^|\s)[-a-z0-9_.]+@(?:[-a-z0-9]+\.)+[a-z]{2,6}(?:\s|$)",re.IGNORECASE)
lib["postcode"] = re.compile("[a-z]{1,2}\d{1,2}[a-z]?\s*\d[a-z]{2}",re.IGNORECASE)
lib["zipcode"] = re.compile("\d{5}(?:[-\s]\d{4})?")
lib["ukdate"] = re.compile \
("[0123]?\d[-/\s\.](?:[01]\d|[a-z]{3,})[-/\s\.](?:\d{2})?\d{2}",re.IGNORECASE)
lib["time"] = re.compile("\d{1,2}:\d{1,2}(?:\s*[aApP]\.?[mM]\.?)?")
lib["fullurl"] = re.compile("https?://[-a-z0-9\.]{4,}(?::\d+)?/[^#?]+(?:#\S+)?",re.IGNORECASE)
lib["visacard"] = re.compile("4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["mastercard"] = re.compile("5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["phone"] = re.compile("0[-\d\s]{10,}")
lib["ninumber"] = re.compile("[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-z]",re.IGNORECASE)
lib["isbn"] = re.compile("(?:[\d]-?){9}[\dxX]")
  '''
  

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
