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
import array

from utils import xrange
import memory_dumper
import signature 

log = logging.getLogger('pattern')


class Sequences:
  def __init__(self, sig, size, cacheAll=True):
    self.size = size
    self.sig = sig
    self.sets={} # key is sequence len
    self.cacheAll=cacheAll
    self.findUniqueSequences(sig)
          
  def findUniqueSequences(self, sig):
    log.debug('number of intervals: %d'%(len(sig)))
    
    sig_set = set(sig)
    log.debug('number of unique intervals value: %d'%(len(sig_set)) )
    self.makeOne(sig)
    
  def makeOne(self, sig ):
    # create the tuple      
    seqlen = self.size
    #seqs =  [ tuple([sig[i+y] for y in range(0, seqlen)]) for i in xrange(0, len(sig)-seqlen+1) ] 
    self.seqs =  [ tuple(sig[i:i+seqlen]) for i in xrange(0, len(sig)-seqlen+1) ] 
    #save them
    self.sets[seqlen] = set(self.seqs)
    log.debug('number of unique sequence len %d : %d'%(seqlen, len(self.sets[seqlen])))
  
  def getSeqs(self):
    if not hasattr(self, 'seqs'):
      self.seqs =  [ tuple(sig[i:i+seqlen]) for i in xrange(0, len(sig)-seqlen+1) ] 
    

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
    return self.sig1[self.offset_sig1:self.offset_sig1+nb]
  
  def __len__(self):
    return len(self.sequence)
  def __str__(self):
    return '<PinnedOffsets 0x%x,0x%x +%d bytes/%d pointers>' %( self.offset_sig1,self.offset_sig2, self.nb_bytes, len(self.sequence)+1 )

def getHeap(dumpfile):
  #log.info('Loading the mappings in the memory dump file.')
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
    f = file(fname+'.pinned','r')
    nb = os.path.getsize(f.name)/4 # simple
    #sig = pickle.load(file(fname+'.pinned','r'))
    sig = array.array('L')
    sig.fromfile(f,nb)
  else:
    pointerSearcher = signature.PointerSearcher(heap)
    sig = array.array('L')
    #p_addr = pointerSearcher.search()
    last=0
    for i in pointerSearcher:
      sig.append(i-last) # save intervals between pointers
      last=i
    sig.pop(0)
    #pickle.dump(sig, file(fname+'.pinned','w'))
    sig.tofile(file(fname+'.pinned','w'))
  return sig



def make(opts, heap1, heap2, heap3):
  log.info('Make the signature.')
  
  sig1 = getSig(heap1, opts.dumpfile1.name)
  log.info('pinning offset list created for heap 1.')
    
  sig2 = getSig(heap2, opts.dumpfile2.name)
  log.info('pinning offset list created for heap 2.')

  sig3 = getSig(heap3, opts.dumpfile3.name)
  log.info('pinning offset list created for heap 3.')

  #cacheValues1 = idea1(sig1,sig2, printStatus)
  #reportCacheValues(cacheValues1)
  #saveIdea(opts, 'idea1', cacheValues1)

  cacheValues2 = idea2(sig1,sig2, sig3, printStatus)
  reportCacheValues(cacheValues2)
  saveIdea(opts, 'idea2', cacheValues2)


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


def idea2(sig1, sig2, sig3, stepCb): 
  '''
  On identifie les sequences d'intervalles longues, et on essaye de pinner
  celle-ci entre les multiples dump.
  modulo les false positives, qui pollue ou diminue le common set, 
  on se retrouve avec des PinnedOffsets tres interessants.
  les sequences se chevauchent beacuoup, [n:n+10] versus [n+1:n+11], 
  il doit donc etre possible de :
  a) reduire le nombre de common sequences en concatenant les sequences
  b) detecter un offset/les offsets de fin des structures. 
  on en revient a l'idea 1, comparaison de subsequences,
  sauf que l'on peut utiliser des comparaisons de tuples/de listes pour optim.
  Mais on en revient au fait qu'il faut refixer chaque common sequences en rapport
  avec un offset dans la signature pour evaluer la sequence 'in place'.
  '''
  cacheValues2 = {}
  length = 20
  checkIncremental=False
  seqs_sig1 = Sequences(sig1, length, False)
  seqs_sig2 = Sequences(sig2, length, False)
  seqs_sig3 = Sequences(sig3, length, False)
  
  if checkIncremental:
    for l in range(2,length+1) :
      common = seqs_sig1.sets[l] &   seqs_sig2.sets[l] &   seqs_sig3.sets[l]
      log.debug('Common sequence of length %d: %d'%(l, len(common)))
  else:  
    common = seqs_sig1.sets[length] &   seqs_sig2.sets[length] &   seqs_sig3.sets[length]
    log.debug('Common sequence of length %d: %d'%(length, len(common)))
  
  # maintenant il faut mapper le common set sur l'array original, 
  # on peut iter(sig)
  #for seq in common:
  #  saveSequence(seq[0], cacheValues2, sig1, offset1, sig2, offset2, match_len)
  
  
  #saveSequence(value1, cacheValues2, sig1, offset1, sig2, offset2, match_len)

  return cacheValues2
  
  
def idea1(sig1, sig2, stepCb):
  '''
    on a pinner chaque possible pointeur vis a vis de sa position relative au precedent pointer.
    Si une structure contient deux ou plus pointers, on devrait donc retrouver 
    une sequence de position relative comparable entre heap 1 et heap 2.
    On a donc reussi a pinner une structure.
    
    modulo les pointer false positive, sur un nombre important de dump, on degage
    des probabilites importantes de detection.
  '''
  step = len(sig1)/100
  log.info('looking for related pointers subsequences between heap1(%d) and heap2(%d)'%(len(sig1),len(sig2)))
  cacheValues1 = {}
  # first pinning between pointer 1 value and pointer value 2
  for offset1 in prioritizeOffsets(sig1): #xrange(0, len(sig1)): # do a non linear search
    if (offset1 % step) == 0:
      stepCb(offset1, cacheValues1)
    # TODO : if value1 in cache, copy Pinned Offsets to new sig1 offset and continue
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
  pickle.dump(results, file(name,'w'))
  

def reportCacheValues( cache ):
  for k,v in cache.items():
    print 'For %d bytes between possible pointers, there is %d PinnedOffsets '%(k, len(v))
    poffs = sorted(v, reverse=True)
    n = min(5, len(v))
    print '  - the %d longuest sequences are '%(n)
    for poff in poffs[:n]:
      print '\t', poff,
      if len(poff) > 100 :
        print poff.pinned(5)
      else:
        print ''
    print ''

def printStatus(offset1, cache):
  print 'Reading offset %d'%(offset1)
  reportCacheValues(cache)


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
