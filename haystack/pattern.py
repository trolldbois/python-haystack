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
    self.name = os.path.basename(dumpFilename)

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
      # save first offset
      last = 0
      for i in pointerSearcher:
        sig.append(i-last) # save intervals between pointers
        last=i
      sig.pop(0)
      sig.tofile(file(myname,'w'))
    self.sig = sig
    return

  def getAddressForOffset(self, offset):
    ''' 
    sum all intervals upto the offset. that give us the relative offset.
    add to dump.start , and we have the vaddr
    '''
    return self.dump.start + reduce(lambda x,y: x+y, self.sig[:offset+1] )

  def __len__(self):
    return len(self.sig)
  def __str__(self):
    return "<Signature '%s'>"%(self.name)
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
  def __len__(self):
    return len(self.signature)-self.size
    
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
    self.vaddr = None
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
  def __contains__(self,other):
    if not isinstance(other, PinnedPointers):
      raise ValueError
    if other.offset in xrange(self.offset,self.offset+len(self) ) :
      return True
    return False
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
  def vaddr(self):
    if self.vaddr is None:
      self.vaddr = self.sig.getAddressForOffset(self.offset)
    return self.vaddr
  def __str__(self):
    return '<PinnedPointers %s[%d:%d] +%d bytes/%d pointers>' %( self.sig, self.offset,self.offset+len(self), self.nb_bytes, len(self.sequence)+1 )

  @classmethod
  def link(cls, lstOfPinned):
    for i,p1 in enumerate(lstOfPinned):
      for p2 in lstOfPinned[i+1:]:
        p1.addRelated(p2,p2.sig)
        p2.addRelated(p1,p1.sig)
    return


def make(opts):
  log.info('Make the signature.')
  
  sig1 = Signature.fromDumpfile(opts.dumpfile1)
  log.info('pinning offset list created for heap %s.'%(sig1))
    
  sig2 = Signature.fromDumpfile(opts.dumpfile2)
  log.info('pinning offset list created for heap %s.'%(sig2))

  sig3 = Signature.fromDumpfile(opts.dumpfile3)
  log.info('pinning offset list created for heap %s.'%(sig3))

  #cacheValues1 = idea1(sig1,sig2, printStatus)
  #reportCacheValues(cacheValues1)
  #saveIdea(opts, 'idea1', cacheValues1)

  #cacheValues2 = idea2(sig1,sig2, sig3, printStatus)
  ppMapper = PinnedPointersMapper()
  ppMapper.addSignature(sig1)
  ppMapper.addSignature(sig2)
  ppMapper.addSignature(sig3)
  ppMapper.run()
  reportCacheValues(ppMapper.cacheValues2)
  saveIdea(opts, 'idea2', ppMapper.cacheValues2)



class PinnedPointersMapper:
  '''
  a) On identifie les sequences d'intervalles longues ( taille fixe a 20 ).
  b) on trouve les sequences communes a toutes les signatures.
  c) pour chaque offset de chaque signature, on determine un PinnedPointer
      qui couvre la plus grande sequence composee de sequence communes.
   *** Erreur possible: la sequence creee en sig1 n'existe pas en sig2.
          cas possible si sig2 contient A4 et A5 en deux zones distinces ( A5 == A4[1:]+...
          et si sig 1 contient A4A5 en une zone distincte 
          on se retrouve avec sig A4A5 mais sig2.A4 et sig2.A5
          on peut dans ce cas, redecouper sig1 selon le plus petit denominateur commun de sig2
     -> check routine
  d) on linke ces PP entres elles ( central repo serait mieux )
  e) Meta info: on trouve les multiple instances ( same struct, multiple alloc)
  '''
  def __init__(self, sequenceLength=20):
    self.cacheValues2 = {}
    self.signatures = []
    self.signatures_sequences = {}
    self.started = False
    self.common = []
    self.length = sequenceLength
    return
  
  def addSignature(self, sig):
    if self.started:
      raise ValueError("Mapping has stated you can't add new signatures")
    self.signatures.append(sig)
    return
    
  def _findCommonSequences(self, length):
    common = None
    for sig in self.signatures:
      # make len(sig) sub sequences of size <length> ( in .sets )
      self.signatures_sequences[sig] = Sequences(sig, length, False)
      if common is None:
        common = set(self.signatures_sequences[sig].sets[length])
      else:
        common &= self.signatures_sequences[sig].sets[length]
    log.info('Common sequence of length %d: %d seqs'%(length, len(common)))
    return common
      
  def _mapToSignature(self, sig ):    
    # maintenant il faut mapper le common set sur l'array original, 
    # a) on peut iter(sig) jusqu'a trouver une sequence non common.
    # b) reduce previous slices to 1 bigger sequence. 
    # On peut aggreger les offsets, tant que la sequence start:start+<length> est dans common.
    # on recupere un 'petit' nombre de sequence assez larges, censees etre communes.
    sig_aggregated_seqs = []
    sig_uncommon_slice_offset = []
    start = 0
    stop = 0
    i=0
    length = self.length
    seqs_sig1 = self.signatures_sequences[sig]
    common = self.common
    enum_seqs_sig = enumerate(seqs_sig1) # all subsequences, offset by offset
    try:
      while i < len(seqs_sig1): # we wont have a StopIteration...
        for i, subseq in enum_seqs_sig:
          if subseq in common:
            start = i
            #log.debug('Saving a Uncommon slice %d-%d'%(stop,start))
            sig_uncommon_slice_offset.append( (stop,start) )
            break
          del subseq
        # enum is on first valid sequence of <length> intervals
        #log.debug('Found next valid sequence at interval offset %d/%d/%d'%(i,len(sig.sig), len(seqs_sig1) ))
        for i, subseq in enum_seqs_sig:
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
            seqStop = stop+length-1
            pp = savePinned(self.cacheValues2, sig, start, seqStop-start) # we should also pin it in sig2, sig3, and relate to that...
            sig_aggregated_seqs.append( pp ) # save a big sequence
            #log.debug('Saving an aggregated sequence %d-%d'%(start, stop))
            del subseq
            break # goto search next common
        # find next valid interval
      # wait for end of enum
    except StopIteration,e:
      pass
    #done
    #log.debug('%s'%sig1_uncommon_slice_offset)
    log.info('There is %d uncommon slice zones in %s'%( len (sig_uncommon_slice_offset), sig) )
    log.info('There is %d common aggregated sequences == struct types in %s'%( len(sig_aggregated_seqs), sig))

    return sig_uncommon_slice_offset, sig_aggregated_seqs
  
  def _findMultipleInstances(self):
    import itertools
    allpp = sorted([v for l in self.cacheValues2.values() for v in l], reverse=True)
    global unresolved
    unresolved = []
    linked = 0
    multiple = 0
    
    for k, g in itertools.groupby( allpp ):
      l = list(g)
      if len(l) < len(mapper.signatures): # we can have multiple instances btu not less.
        unresolved.extend(l)
        #print 'not same numbers'
        continue
      else:
        allSigs = True
        # we should have all 3 signatures
        found = [pp.sig for pp in l ]
        for s in mapper.signatures:
          if s not in found:
            unresolved.extend(l)
            #print 'not same sigs', s
            allSigs = False
            break
        # if ok, link them all
        if allSigs:
          PinnedPointers.link(l)
          multiple+=1
          linked+=len(l)
          
    unresolved.reverse()

    log.info('Linked %d PinnedPointers, %d unique in all Signatures '%(linked, multiple))
    log.info('left with %d/%d partially unresolved pp'%(len(unresolved), len(allpp) ) )
    return
  
  def _findMultipleInstances_old(self, sig_aggregated_seqs):
    log.debug('check for multiple instances of one structure.')
    multiple=0
    pinnedList = sorted(sig_aggregated_seqs)
    for k, g in itertools.groupby( pinnedList ):
      l = list(g)
      if len(l) > 1:
        offsets = [pp.offset for pp in l ]
        log.debug ('Multiple(%d) instances of %s at intervals offsets %s'%(len(l), k, offsets))
        multiple+=1
        # link them to one another
        PinnedPointers.link(l)
    log.info('  and %d of thoses structs have multiple instances.'%(multiple))
    return

  def run(self): 
    self.started = True
    all_common_pp = []
    
    ### drop 1 : find common sequences
    self.common = self._findCommonSequences(self.length)
    
    ### drop 2: Map sequence to signature, and aggregate overlapping sequences.
    for sig in self.signatures:
      unknown_slices, common_pp = self._mapToSignature(sig ) 
      all_common_pp.extend(common_pp)

    ### drop 3: error case, we have been too optimistic about unicity of common sequence.
    ###   lets try and reduce the errors.
    global cache
    global common
    global mapper
    mapper = self
    common = self.common
    cache = self.cacheValues2
    ### for each structLen, find at least one pp for each sig
    
    ### chance are that only the last interval is botched, so we only have to compare between
    ### pp1.sequence[:-1] and pp2.sequence[:-1] to find a perfect match
    # we nee to find sole pointer. pop all equals in the 3 sigs.
    ### drop 3: Analyze and find multiple instances of the same Sequence
    self._findMultipleInstances()
    
    ### drop 4: Sequence should have been linked, cross-signature. Try to extend them
    ### On peut pas agrandir les sequences. il n"y a plus de common pattern,
    ### Par contre, on peut essayer de trouver des sequences plus courtes dans les
    ### intervalles uncommon_slices

    return 


def t(mapper):

  for k,v in mapper.cacheValues2.items():
    # we have a list of x pp
    if len(v) == len(mapper.signatures):
      # we should have all 3 signatures
      found = [pp.sig for pp in v ]
      for s in mapper.signatures:
        if s not in [found]:
          print '%s not in found'%(s) 
      

  
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

def saveIdea(opts, name, results):
  pickle.dump(results, file(name,'w'))
  

def reportCacheValues( cache ):
  log.info('Reporting info on values on stdout')
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


def tests():
  '''
import pattern 
pattern.main('../outputs/skype.1.a ../outputs/skype.2.a ../outputs/skype.3.a'.split())
cacheValues=pattern.cache
common = pattern.common
mapper = pattern.mapper

'''
  pass

if __name__ == '__main__':
  main(sys.argv[1:])
