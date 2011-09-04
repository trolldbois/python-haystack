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
import itertools

from utils import xrange
import memory_dumper
import signature 

log = logging.getLogger('pattern')


class Signature:
  ''' a dump pointer signature '''
  def __init__(self, dump=None, dumpFilename=None):
    self.dump = dump  
    self.dumpFilename = dumpFilename

  def _getDump(self):
    #log.info('Loading the mappings in the memory dump file.')
    mappings = memory_dumper.load( file(self.dumpFilename,'r'), lazy=True)
    heap = None
    if len(mappings) > 1:
      heap = [m for m in mappings if m.pathname == '[heap]'][0]
    if heap is None:
      raise ValueError('No [heap]')
    self.dump = heap
    return

  def _load(self):
    ## DO NOT SORT LIST. c'est des sequences. pas des sets.
    myname = self.dumpFilename+'.pinned'
    if os.access(myname,os.F_OK):
      # load
      f = file(myname,'r')
      nb = os.path.getsize(f.name)/4 # simple
      #sig = pickle.load(file(fname+'.pinned','r'))
      sig = array.array('L')
      sig.fromfile(f,nb)
    else:
      log.info("Signature has to be calculated. It's gonna take a while.")
      pointerSearcher = signature.PointerSearcher(self.dump)
      sig = array.array('L')
      #p_addr = pointerSearcher.search()
      last=0
      for i in pointerSearcher:
        sig.append(i-last) # save intervals between pointers
        last=i
      sig.pop(0)
      sig.tofile(file(myname,'w'))
    self.sig = sig
    return
    
  @classmethod
  def fromDumpfile(cls, dumpfile):
    inst = Signature(dumpFilename = dumpfile.name)
    inst._getDump()
    inst._load()
    return inst
  @classmethod
  def fromDump(cls, dump):
    inst = Signature(dump = dump)
    inst._load()
    return inst

class Sequences:
  def __init__(self, sig, size, cacheAll=True):
    self.size = size
    self.signature = sig
    self.sig = sig.sig
    self.sets={} # key is sequence len
    self.cacheAll=cacheAll
    self.findUniqueSequences(self.sig)
          
  def findUniqueSequences(self, sig):
    log.debug('number of intervals: %d'%(len(sig)))
    sig_set = set(sig)
    log.debug('number of unique intervals value: %d'%(len(sig_set)) )
    # create the tuple      
    self.sets[self.size] = set(self.getSeqs())
    log.debug('number of unique sequence len %d : %d'%(self.size, len(self.sets[self.size])))
    return
  
  def getSeqs(self):
    if not hasattr(self, 'seqs'):
      seqlen = self.size
      self.seqs =  [ tuple(self.sig[i:i+seqlen]) for i in xrange(0, len(self.sig)-seqlen+1) ]
      seqs =  self.seqs
      return seqs

  def __iter__(self):
    seqlen = self.size
    for i in xrange(0, len(self.sig)-seqlen+1):
      yield tuple(self.sig[i:i+seqlen])
    return

class PinnedOffsets:
  def __init__(self, sequence, sig1, offset_sig1, sig2, offset_sig2):
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

class PinnedPointers:
  def __init__(self, sequence, sig, offset):
    self.sequence = sequence
    self.nb_bytes = reduce(lambda x,y: x+y, sequence)
    self.offset = offset
    self.sig = sig 
    self.relations = {}
  def pinned(self, nb=None):
    if nb is None:
      nb == len(self.sequence)
    return self.sequence[:nb]
  def __len__(self):
    return len(self.sequence)
  def structLen(self):
    return self.nb_bytes
  def __cmp__(self,o):
    if len(self) != len(o):
      return cmp(len(self),len(o) )
    if self.structLen() != o.structLen(): # that means the sequence is different too
      return cmp(self.structLen(), o.structLen())
    if self.sequence != o.sequence: # the structLen can be the same..
      return cmp(self.sequence, o.sequence)
    #else offset is totally useless, we have a match
    return 0
  def addRelated(self,other, sig=None):
    ''' add a similar PinnedPointer from another offset or another sig '''
    if self != other:
      raise ValueError('We are not related PinnedPointers.')
    if sig is None:
      sig = self.sig
    if sig not in self.relations:
      self.relations[sig] = list()
    self.relations[sig].append( other )
    return
  def __str__(self):
    return '<PinnedPointers sig[%d:%d] +%d bytes/%d pointers>' %( self.offset,self.offset+len(self), self.nb_bytes, len(self.sequence)+1 )
  @classmethod
  def link(cls, lstOfPinned):
    for i,p1 in enumerate(lstOfPinned):
      for p2 in lstOfPinned[i+1:]:
        p1.addRelated(p2,p2.sig)
        p2.addRelated(p1,p1.sig)



def make(opts):
  log.info('Make the signature.')
  
  sig1 = Signature.fromDumpfile(opts.dumpfile1)
  log.info('pinning offset list created for heap 1.')
    
  sig2 = Signature.fromDumpfile(opts.dumpfile2)
  log.info('pinning offset list created for heap 2.')

  sig3 = Signature.fromDumpfile(opts.dumpfile3)
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
  seqs_sig1 = Sequences(sig1, length, False)
  seqs_sig2 = Sequences(sig2, length, False)
  seqs_sig3 = Sequences(sig3, length, False)
  
  common = seqs_sig1.sets[length] &   seqs_sig2.sets[length] &   seqs_sig3.sets[length]
  log.info('Common sequence of length %d: %d'%(length, len(common)))
  
  # maintenant il faut mapper le common set sur l'array original, 
  # a) on peut iter(sig) jusqu'a trouver une sequence non common.
  # b) reduce previous slice to 1 bigger sequence. 
  # comme tout les sequences sont communes, on peut les aggreger sans regarder l'offset.
  sig1_aggregated_seqs = []
  sig1_uncommon_slice_offset = []
  start = 0
  stop = 0
  i=0
  enum_seqs_sig1 = enumerate(seqs_sig1) # all subsequences, offset by offset
  try:
    while i < len(sig1.sig) - length:
      for i, subseq in enum_seqs_sig1:
        if subseq in common:
          start = i
          #log.debug('Saving a Uncommon slice %d-%d'%(stop,start))
          sig1_uncommon_slice_offset.append( (stop,start) )
          break
        del subseq
      # enum is on first valid sequence of <length> intervals
      #log.debug('Found next valid sequence at interval offset %d'%(i))
      for i, subseq in enum_seqs_sig1:
        if subseq in common:
          del subseq
          continue
        else: # the last interval in the tuple of <length> intervals is not common
          # so we need to aggregate from [start:stop+length]
          # there CAN be another common slice starting between stop and stop+length.
          # (1,2,3,4) is common , (1,2,3,4,6) is NOT common because of the 1, (2,3,4,6) is common.
          # next valid slice is at start+1 
          # so Yes, we can have recovering Sequences
          stop = i # end aggregation slice
          seqStop = stop+length
          pp = savePinned(cacheValues2, sig1, start, seqStop-start) # we should also pin it in sig2, sig3, and relate to that...
          sig1_aggregated_seqs.append( pp ) # save a big sequence
          #log.debug('Saving an aggregated sequence %d-%d'%(start, stop))
          del subseq
          break # goto search next common
      # find next valid interval
    # wait for end of enum
  except StopIteration,e:
    pass
  #done
  #log.debug('%s'%sig1_uncommon_slice_offset)
  log.info('There is %d uncommon slice zones'%( len (sig1_uncommon_slice_offset)) )
  log.info('There is %d common aggregated sequences == struct types'%( len(sig1_aggregated_seqs)))
  
  #log.debug('check for multiple instances of one structure.')
  multiple=0
  pinnedList = sorted(sig1_aggregated_seqs)
  for k, g in itertools.groupby( pinnedList ):
    l = list(g)
    if len(l) > 1:
      offsets = [pp.offset for pp in l ]
      log.debug ('Multiple(%d) instances of %s at intervals offsets %s'%(len(l), k, offsets))
      multiple+=1
      # link them to one another
      PinnedPointers.link(l)
  log.info('  and %d of thoses structs have multiple instances.'%(multiple))

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
  # sort by key
  keys = sorted(cache.keys(), reverse=True)
  for k in keys:
    v = cache[k]
    print 'For %d bytes between possible pointers, there is %d PinnedOffsets '%(k, len(v))
    # print nicely top 5
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
  cacheValues[value].append( PinnedOffsets( pinned, sig1, offset1, sig2, offset2) )
  return

def savePinned(cacheValues, sig, offset, match_len ):
  pinned = sig.sig[offset:offset+match_len]
  pp = PinnedPointers( pinned, sig, offset)
  s = pp.structLen() 
  if s not in cacheValues:
    cacheValues[s] = list()
  cacheValues[s].append( pp )
  return pp 



def search(opts):
  #
  make(opts)
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
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
