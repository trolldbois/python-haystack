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

from haystack import dump_loader
from haystack import argparse_utils
from haystack.utils import xrange
from haystack.reverse import utils

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger('pointerfinder')


def _openDumpfile(dumpfile):
  # load memorymapping
  mappings = dump_loader.load(dumpfile)
  # TODO : make a mapping chooser 
  stack, heap = None, None
  if len(mappings) > 1:
    for m in mappings:
      if m.pathname == '[heap]':
        heap = m 
      if m.pathname == '[stack]':
        stack = m 
  if heap is None or stack is None:
    log.info('Heap or stack has not been found( head:%s stack:%s'%(heap, stack))
    return None
  return heap,stack,mappings

def mergeDump(dumpFile):
  log.info('Loading the mappings in the memory dump file.')
  mappings = _openDumpfile(dumpFile)
  if mappings is None:
    return
  heap,stack,mappings = mappings
  #log.info('Make the signature.')
  #sigMaker = SignatureMaker(mapping)
  #sig = sigMaker.search()

  # get pointers in stack
  stackSearcher = PointerSearcher(stack)
  stackSearcher.setTargetMapping(heap)
  heapSearcher = PointerSearcher(heap)
  pointersFromHeap  = heapSearcher.search()
  pointersFromStack = stackSearcher.search()
  pointersFromHeap = sorted(pointersFromHeap)
  pointersFromStack = sorted(pointersFromStack)
  log.info('%d heap pointers in stack'%( len(pointersFromStack) ))
  log.info('%d heap pointers in heap'%( len(pointersFromHeap) ))
  # common ones
  intersex = set(pointersFromHeap) & set(pointersFromStack)
  log.info('%d heap pointers in both'%( len(intersex) ))
  # all
  allpointers = []
  #allpointers.extend(pointersFromHeap)
  allpointers.extend(pointersFromStack)
  allpointers = sorted(set(allpointers))
  # give intervals between pointers
  intervals=[]
  for p in xrange(1,len(allpointers)-1):
    val = allpointers[p] - allpointers[p-1]
    intervals.append(val)
  return



'''
AbstractSearcher, abstract impl, return vaddr of match on iter(), search()
AbstractEnumerator, abstr impl, return offset,value of match on iter(), search()
                          expect a boolean, value tuple from testMatch


'''




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
    #log.info('processing vaddr 0x%x'%(val))
    pass

class AbstractSearcher(FeedbackGiver):
  ''' Search for something in memspace. 
    feedback(step, val) will be called each step  
  '''
  WORDSIZE = ctypes.sizeof(ctypes.c_void_p) # config
  
  def __init__(self, searchMapping, steps=10, feedback=None):
    '''
      search in searchMapping for something.
    '''
    self.searchMapping = searchMapping
    self.targetMapping = searchMapping
    self._initSteps(self.searchMapping.start, self.searchMapping.end, steps)

  def _initSteps(self, start, end, steps):
    ''' calculate the vaddr at which feedback would be given '''
    self.steps = [o for o in range(start,end, (end-start)/steps)] # py 3 compatible
    return

  def setTargetMapping(self, m):
    self.targetMapping = m
    return
  def getTargetMapping(self):
    return self.targetMapping
  
  def _checkSteps(self, step):
    if len(self.steps) == 0:
      return
    if step > self.steps[0]:
      val = self.steps.pop(0)
      self.feedback(step, val)
    return
  
  def getSearchMapping(self):
    return self.searchMapping
  
  def search(self):
    ''' find all valid matches offsets in the memory space '''
    self.values = set()
    log.debug('search %s mapping for matching values'%(self.getSearchMapping()))
    self.values = [t for t in self]
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    log.debug('iterate %s mapping for matching values'%(self.getSearchMapping()))
    for vaddr in xrange(self.getSearchMapping().start, self.getSearchMapping().end, self.WORDSIZE):
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
    word = self.getSearchMapping().readWord(vaddr)
    if word in self.getTargetMapping():
      return True
    return False


class AbstractEnumerator(AbstractSearcher):
  ''' return vaddr,value 
  expect a boolean, value tuple from testMatch'''
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    start = self.getSearchMapping().start
    for vaddr in xrange(start, self.getSearchMapping().end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      b,val = self.testMatch(vaddr) # expect a boolean, value tuple from testMatch
      if b:
        yield (vaddr, val )
    return
  
  def testMatch(self, vaddr):
    ''' implement this methods to test for a match at that offset 
    should return boolean, value
    '''
    raise NotImplementedError

class PointerEnumerator(AbstractEnumerator):
  def testMatch(self, vaddr):
    word = self.getSearchMapping().readWord(vaddr)
    if word in self.getTargetMapping():
      return True, word
    return False, None


class NullSearcher(AbstractSearcher):
  ''' 
  Search for Nulls words in memspace.
  '''
  def testMatch(self, vaddr):
    word = self.getSearchMapping().readWord(vaddr)
    if word == 0:
      return True
    return False


def merge(opt):
  mergeDump(opt.dumpfile)
  pass

def reverseLookup(opt):
  from haystack.reverse import reversers
  log.info('[+] Load context')
  context = reversers.getContext(opt.dumpname)
  addr = opt.struct_addr
  while True:
    log.info('[+] find offsets of struct_addr:%x'%(addr))
    i = -1
    structs = set()
    try:
      structs = context.listStructuresForPointerValue(addr)
    except ValueError,e:
      log.info('[+] Found no structures.')
      return
    log.info('[+] Found %d structures.'%( len(structs) ))
    for st in structs:
      st.decodeFields()
      print st.toString()
    # wait for input
    import code
    code.interact(local=locals())
    sys.stdin.read(1)
    addr = st._vaddr
  return
  
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-pointer-tools', description='Tools around pointers.')
  rootparser.add_argument('dumpname', type=argparse_utils.readable, action='store', help='Source memory dump by haystack.')

  subparsers = rootparser.add_subparsers(help='sub-command help')
  reverse = subparsers.add_parser('reverse', help='reverse pointer lookup - find structures that contains struct_addr value')
  reverse.add_argument('struct_addr', type=argparse_utils.int16, action='store', help='target structure addresse')
  reverse.set_defaults(func=reverseLookup)  

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
