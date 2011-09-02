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

from utils import xrange
import memory_dumper
import signature 

log = logging.getLogger('pattern')



class PinnedOffsets:
  def __init__(self, value, sequence, sig1, offset_sig1, sig2, offset_sig2):
    self.value = value
    self.sequence = sequence
    self.nb_bytes = reduce(lambda x,y: x+y, sequence)
    self.offset_sig1 = offset_sig1
    self.offset_sig2 = offset_sig2
    self.sig1 = sig1
    self.sig2 = sig2
  def pinned(self, nb=None):
    if nb is None:
      nb == len(self.sequence)
    log.debug(self.sig1[self.offset_sig1:self.offset_sig1+nb])
    log.debug(self.sig2[self.offset_sig2:self.offset_sig2+nb])
    return self.sig1[self.offset_sig1:self.offset_sig1+nb]
  
  def __len__(self):
    return len(self.sequence)
  def __str__(self):
    return '<PinnedOffsets %d bytes, %d pointers>' %( self.nb_bytes, len(self.sequence)+1 )

def getHeap(dumpfile):
  log.info('Loading the mappings in the memory dump file.')
  mappings = memory_dumper.load(dumpfile, lazy=True)
  heap = None
  if len(mappings) > 1:
    heap = [m for m in mappings if m.pathname == '[heap]'][0]
  if heap is None:
    raise ValueError('No [heap]')
  return heap

def getSig(heap, fname):
  ## DO NOT SORT LIST. c'est des sequences. pas des sets.
  if os.access(fname+'.pinned',os.F_OK):
    # load
    sig = pickle.load(file(fname+'.pinned','r'))
  else:
    pointerSearcher = signature.PointerSearcher(heap)
    sig = []
    #p_addr = pointerSearcher.search()
    last=0
    for i in pointerSearcher:
      sig.append(i-last)
      last=i
    sig.pop(0)
    pickle.dump(sig, file(fname+'.pinned','w'))
  return sig

def make(opts, heap1, heap2, heap3):
  log.info('Make the signature.')
  
  sig1 = getSig(heap1, opts.dumpfile1.name)
  log.info('pinning offset list created for heap 1.')
    
  sig2 = getSig(heap2, opts.dumpfile2.name)
  log.info('pinning offset list created for heap 2.')

  sig3 = getSig(heap3, opts.dumpfile2.name)
  log.info('pinning offset list created for heap 3.')

  cacheValues1 = idea1(sig1,sig2, printStatus)
  reportCacheValues(cacheValues1)
  saveIdea(opts, 'idea1', cacheValues1)


def prioritizeOffsets(sig):
  indexes = []
  log.debug('Prioritize large intervals.')
  for val in sorted(set(sig), reverse=True): # take big intervals first
    tmp = []
    i = 0
    while True:
      try:
        i = sig.index(val, i+1)
      except ValueError,e:
        break
      except IndexError,e:
        break
      tmp.append(i)
    indexes.extend(tmp)
  return indexes
  

def idea1(sig1, sig2, stepCb):
  '''
    on a pinner chaque possible pointeur vis a vis de sa position relative au precedent pointer.
    Si une structure contient deux ou plus pointers, on devrait donc retrouver 
    une sequence de position relative comparable entre heap 1 et heap 2.
    On a donc reussi a pinner une structure.
    
    modulo les pointer false positive, sur un nombre important de dump, on degage
    des probabilites importantes de detection.
  '''
  step = len(sig1)/10
  log.info('looking for related pointers subsequences between heap1(%d) and heap2(%d)'%(len(sig1),len(sig2)))
  cacheValues1 = {}
  # first pinning between pointer 1 value and pointer value 2
  for offset1 in prioritizeOffsets(sig1): #xrange(0, len(sig1)): # do a non linear search
    if (offset1 % step) == 0 or True:
      stepCb(offset1, cacheValues1)
    # please cache res for value1
    value1 = sig1[offset1]
    offset2=-1
    while True:
      try:
        offset2 += 1
        offset2 = sig2.index(value1, offset2)
      except ValueError,e:
        log.debug('no more value1(%d) in sig2, goto next value1'%(value1))
        break # goto next value1
      # on check le prefix sequence commune la plus longue
      off1 = offset1+1
      off2 = offset2+1
      match_len = 1 # match_len de 1 are interesting, to be validated against content... + empiric multiple dumps measurements
      try:
        while sig1[off1] == sig2[off2]:
          off1 += 1
          off2 += 1
          match_len+=1
        # not equals
        #log.debug('Match stop - Pinned on %d intervals (first %d)'%(match_len, value1))
        saveSequence(value1, cacheValues1, sig1, offset1, sig2, offset2, match_len)
      except IndexError, e: # boundary stop, we should have a pretty nice pinning here
        log.debug('Boundary stop - Pinned on %d intervals'%(match_len))
        saveSequence(value1, cacheValues1, sig1, offset1, sig2, offset2, match_len)
      pass # continue next offset2 for value1
    #
    pass  # continue next value1
  #
  return cacheValues1


def saveIdea(opts, name, results):
  pickle(results, file(name,'w'))
  

def reportCachesValues( cache ):
  for k,v in cache.items():
    print 'For %d bytes between possible pointers, there is %d PinnedOffsets '%(k, len(v))
    poffs = sorted(v, reverse=True)
    n = min(5, len(v))
    print '  - the %d longuest sequences are '%(n)
    for poff in poffs[:n]:
      print '\t', poff,
      if len(poff) > 100 :
        print poff.pinned(5)
    print ''

def printStatus(offset1, cache):
  print 'Reading offset %d'%(offset1)
  reportCachesValues(cache)


def saveSequence(value, cacheValues, sig1, offset1, sig2, offset2, match_len ):
  pinned = sig1[offset1:offset1+match_len]
  if value not in cacheValues:
    cacheValues[value] = list()
  #cache it
  cacheValues[value].append( PinnedOffsets(value, pinned, sig1, offset1, sig2, offset2) )
  return



def search(opts):
  #
  heap1 = getHeap(opts.dumpfile1)
  heap2 = getHeap(opts.dumpfile2)
  heap3 = getHeap(opts.dumpfile3)
  make(opts, heap1,heap2, heap3)
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-pattern', description='Do a discovery structure pattern search.')
  #rootparser.add_argument('sigfile', type=argparse.FileType('wb'), action='store', help='The output signature filename.')
  rootparser.add_argument('dumpfile1', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  rootparser.add_argument('dumpfile2', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  rootparser.add_argument('dumpfile3', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  rootparser.set_defaults(func=search)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
