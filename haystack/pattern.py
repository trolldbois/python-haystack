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
import numbers

from utils import xrange
import memory_dumper
import signature 

log = logging.getLogger('pattern')

OUTPUTDIR='../outputs/'

def make(opts):
  log.info('Make the signature.')
  ppMapper = PinnedPointersMapper()  
  for dumpfile in opts.dumpfiles:
    sig = Signature.fromDumpfile(dumpfile)
    log.info('pinning offset list created for heap %s.'%(sig))
    ppMapper.addSignature(sig)
    
  log.info('Find similar vectors between pointers on all signatures.')
  ppMapper.run()
  #reportCacheValues(ppMapper.cacheValues2)
  #saveIdea(opts, 'idea2', ppMapper.cacheValues2)

  ## we have :
  ##  resolved PinnedPointers on all sigs in ppMapper.resolved
  ##  unresolved PP in ppMapper.unresolved
  
  ## next step
  log.info('Pin resolved PinnedPointers to their respective heap.')



class Signature:
  ''' 
  Wraps the list of intervals between pointers identified in the dumpfile.
  '''
  def __init__(self, dump=None, dumpFilename=None):
    self.dump = dump  
    self.dumpFilename = dumpFilename
    self.name = os.path.basename(dumpFilename)
    self.addressCache = {}

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
      sig = array.array('L')
      sig.fromfile(f,nb)
      log.debug("%d Signature intervals loaded from cache."%( len(sig) ))
    else:
      log.info("Signature has to be calculated for %s. It's gonna take a while."%(self.name))
      pointerSearcher = signature.PointerSearcher(self.dump)
      self.WORDSIZE = pointerSearcher.WORDSIZE
      sig = array.array('L')
      # save first offset
      last = self.dump.start
      for i in pointerSearcher: #returns the vaddr
        sig.append(i-last) # save intervals between pointers
        last=i
      sig.tofile(file(myname,'w'))
    self.sig = sig
    #self.addressCache[-1] = self.dump.start
    self.addressCache[0] = self.dump.start # previous pointer of interval 0 is start of mmap
    self._loadAddressCache()
    return

  def _loadAddressCache(self):
    ## DO NOT SORT LIST. c'est des sequences. pas des sets.
    myname = self.dumpFilename+'.pinned.vaddr'
    if os.access(myname,os.F_OK):
      addressCache = pickle.load(file(myname,'r'))
      log.debug("%d Signature addresses loaded from cache."%( len(addressCache) ))
      self.addressCache.update(addressCache)
    else: # get at least 10 values
      for i in xrange(0, len(self), len(self)/10):
        self.getAddressForPreviousPointer(i)
      self._saveAddressCache()
    return

  def _saveAddressCache(self):
    myname = self.dumpFilename+'.pinned.vaddr'
    pickle.dump(self.addressCache, file(myname,'w'))

  def getAddressForPreviousPointer(self, offset):
    ''' 
    sum all intervals upto the offset. that give us the relative offset.
    add to dump.start , and we have the vaddr
    We need to sum all up to offset not included.
    it we include the offset, we get the second pointer vaddr.
    '''
    # use cache my friends
    if offset in self.addressCache :
      return self.addressCache[offset]
    # get closest one
    keys = sorted(self.addressCache)
    keys = list(itertools.takewhile(lambda x: x < offset, keys)) 
    last = keys[-1] # take the closest
    startValue = self.addressCache[last] ## == addr(last-1)
    subseq = self.sig[last:offset] # we are not interested in adding offset interval. that would give us the second pointer address 
    #newsum = startValue + reduce(lambda x,y: x+y, subseq)
    #self.addressCache[offset] = newsum
    ## be proactive +/- 40 Mo
    newsum = startValue
    for i in range(last, offset):
      newsum+=self.sig[i]
      self.addressCache[i+1] = newsum
    ## be proactive
    return newsum

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

class Sequences:
  ''' 
  Make a list of sequences of interval for each interval in the signature.
  '''
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


class PinnedPointers:
  '''
    A variable length sequence of intervals between pointers.
    It already pinned at a specific offset of a signature, 
    so you migth find several instance(p1,p2) at different offset, but with the same sequence
    and therefore equal values. p1 == p2.
    It is easily pin onto the initial dump/heap by getAddress()
  '''
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
  def getAddress(self, numOffset=0):
    ''' 
    return the vaddr of pointer <numOffset>. 
      by default numOffset == 0 , returns the vaddr of the first interval 
      ( that migth be the first or second pointer in the struct )
    '''
    if self.vaddr is None:
      if numOffset >= len(self.sequence):
        raise IndexError
      self.vaddr = self.sig.getAddressForPreviousPointer(self.offset)
    if numOffset != 0:
      return self.sig.getAddressForPreviousPointer(self.offset+numOffset)
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
    
  def _findCommonSequences(self):
    log.info('Looking for common sequence of length %d'%(self.length))
    common = None
    # make len(sig) sub sequences of size <length> ( in .sets )
    for sig in self.signatures:
      self.signatures_sequences[sig] = Sequences(sig, self.length, False)
      if common is None:
        common = set(self.signatures_sequences[sig].sets[self.length])
      else:
        common &= self.signatures_sequences[sig].sets[self.length]
    log.info('Common sequence of length %d: %d seqs'%(self.length, len(common)))
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
    unresolved = []
    linkedPP  = []
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
          linkedPP.extend(l)
          multiple+=1
          linked+=len(l)
          
    unresolved = sorted(unresolved,reverse=True)
    linkedPP = sorted(linkedPP,reverse=True)
    
    self.unresolved = unresolved
    self.resolved = linkedPP
    log.info('Linked %d PinnedPointers, %d unique in all Signatures '%(linked, multiple))
    log.info('left with %d/%d partially unresolved pp'%(len(unresolved), len(allpp) ) )
    #cache to disk
    #cacheToDisk(self.resolved,'pinned-resolved')
    #cacheToDisk(self.unresolved,'pinned-unresolved')
    return
  

  def run(self): 
    self.started = True
    all_common_pp = []
    
    CACHE='pinned-resolved'
    CACHE2='pinned-unresolved'
    global mapper
    mapper = self
    
    ### drop 1 : find common sequences
    self.common = self._findCommonSequences()
      
    ### drop 2: Map sequence to signature, and aggregate overlapping sequences.
    for sig in self.signatures:
      unknown_slices, common_pp = self._mapToSignature(sig ) 
      all_common_pp.extend(common_pp)

    ### drop 3: error case, we have been too optimistic about unicity of common sequence.
    ###   lets try and reduce the errors.
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
    self._pinResolved()
    return 


  ##################################3 STEP 2 , pin them on the wall/heap
    
  def _pinResolved(self ):
    caches = {}
    for sig in self.signatures[:]:
      a = Dummy()
      resolved_for_sig = [ pp for pp in self.resolved if pp.sig == sig ]
      unresolved_for_sig = [ pp for pp in self.unresolved if pp.sig == sig ]
      log.debug('making pinned')
      pinned = [AnonymousStructRange(pp) for pp in resolved_for_sig]
      log.debug('making pinned_start')
      pinned_start = sorted([pp.getAddress() for pp in resolved_for_sig])
      log.debug('making pinned_lightly')
      pinned_lightly = [AnonymousStructRange(pp) for pp in unresolved_for_sig]
      log.debug('making pinned_lightly_start')
      pinned_lightly_start = sorted([pp.getAddress() for pp in unresolved_for_sig])
      # save it
      a.pinned = pinned
      a.pinned_start = pinned_start
      a.pinned_lightly = pinned_lightly
      a.pinned_lightly_start = pinned_lightly_start
      caches[sig] = a
    #log.debug('Overlapping sequences can happen. we will filter them later using a tree of structures.')
    #for i, pp in enumerate(pinned):
    #  if pp.start in pinned[i+1:]:
    #    pass
    
    sig = self.signatures[0]
    pinned = caches[sig].pinned
    pinned_start = caches[sig].pinned_start
    pinned_lightly = caches[sig].pinned_lightly
    pinned_lightly_start = caches[sig].pinned_lightly_start
    ## for as in pinned, get pointers values and make a tree
    log.debug('Going through pointers')
    startsWithPointer = 0
    startsMaybeWithPointer = 0
    pointsToStruct = 0
    pointsToStruct2 = 0
    self.startTree = []
    self.startTree2 = []
    self.tree = []
    self.tree2 = []
    startsWithPointerList = self.startTree
    startsMaybeWithPointerList = self.startTree2
    pointsToStructList = self.tree
    pointsToStructList2 = self.tree2
    for i,ap in enumerate(pinned):
      pts = ap.getPointersValues()
      me = ap.pinnedPointer.getAddress()
      if pts[0] == me:
        log.debug('first pointer of pp %i is an autopointer on myself/C++ ?'%(i))
      for j,ptr in enumerate(pts):
        sub = pinned_start#[i+1:]
        if ptr in sub:
          log.debug('Lucky guess s:%d, p:%d, we find a pointer to the start of %d PinnedPointer struct.'%(i, j, sub.count(ptr))) 
          startsWithPointer+=1
          startsWithPointerList.append((ap,j))
          # check if the same struct in sig2, sig3... points to the same target struct
          self._checkRelations(caches, ptr, ap.pinnedPointer, j) 
          # probably else:
        elif ptr in pinned_lightly_start:
          sub = pinned_lightly_start#[i+1:]
          log.debug('Lucky guess s:%d, p:%d we find a pointer to %d maybe-PinnedPointer struct.'%(i, j, sub.count(ptr)))
          startsMaybeWithPointer+=1
          startsMaybeWithPointerList.append((ap,j))
          # probably else:
        elif ptr in pinned:
          sub = pinned
          #log.debug('normal guess s:%d, p:%d, we find a pointer to the start or CONTENT of %d PinnedPointer struct. %x'%(i, j, sub.count(ptr), ptr))
          pointsToStruct+=1
          pointsToStructList.append((ap,j))
        elif ptr in pinned_lightly:
          sub = pinned_lightly
          #log.debug('normal guess s:%d, p:%d, we find a pointer to the start or CONTENT of %d PinnedPointer MAYBE-struct.'%(i, j, sub.count(ptr)))
          pointsToStruct2+=1
          pointsToStructList2.append((ap,j))
        else:
          #log.debug('That pointer s:%d, p:%d is lost in the void..'%(i, j))
          # check nearest in pinned
          try:
            first_addr = itertools.dropwhile(lambda x: x < ptr, pinned_start).next()
            nearest = pinned[pinned.index(first_addr)]
          except StopIteration,e:
            first_addr = -1
            pass
          #log.debug(nearest.start-ptr)
          # check in lightly
          try:
            first_addr_l = itertools.dropwhile(lambda x: x < ptr, pinned_lightly_start).next()
            nearest_lightly = pinned_lightly[pinned_lightly.index(first_addr_l)]
          except StopIteration,e:
            first_addr_l = -1
            pass
          #log.debug(nearest_lightly.start-ptr)
          if first_addr_l > first_addr_l:
            s = 'pinned'
          else:
            s = 'pinned_lightly'
            nearest = nearest_lightly
          #log.debug('Nearest struct is at %d bytes in %s'%( min(first_addr_l, first_addr_l)-ptr , s))
          offset = nearest.start-ptr
          if  offset < 64:
            log.info('Found a probable start of struct at %d bytes earlier'%(offset))
          
    # pointer to self means c++ object ?
    sig._saveAddressCache()

    log.debug('We have found %d pointers to pinned structs'%(startsWithPointer))
    log.debug('We have found %d pointers to pinned maybe-structs'%(startsMaybeWithPointer))
    return

  def _checkRelations(self, cache, ptr, pp, pointerIndex ) :
    '''
      go through all related pinned pointers of the other signatures.
      check if the targeted pinnedpointer for the pointer number <pointerIndex> is the same pinnedPointer
      than in the sig1
    '''
    ok = False
    mypinned = cache[pp.sig].pinned
    anontargetPP = mypinned[mypinned.index(ptr)]
    targetPP = anontargetPP.pinnedPointer

    for sig in self.signatures:
      ok = False
      if sig == pp.sig:
        continue
      #log.debug('checking relations %d %s'%(len(pp.relations),pp.relations.keys()) )
      relatedPPs = pp.relations[sig]
      relatedTargetPPs = targetPP.relations[sig]
      # TODO: if there a multiple instance, what should we check ?
      if len(relatedPPs) >1:
        log.debug('We have more than one relatedPP to target')
      tgtPtrs = [AnonymousStructRange(relatedPP).getPointersValues()[pointerIndex] for relatedPP in relatedPPs]

      ## check all startAddress for relatedTargetPPs, to find relatedPP.pointerValue[index]
      for relatedTargetPP in relatedTargetPPs:
        addr = AnonymousStructRange(relatedTargetPP).start
        if addr in tgtPtrs:
          log.debug('** found a perfect match between %s and %s'%(pp.sig, relatedTargetPP.sig))
          ok = True
          break

      ## not ok, we did not find a related match.
      ## that means the pinnedPointer 
      if not ok:
        for tgtPtr in tgtPtrs:
          #log.debug('NOT found a match between %s and %s'%(pp.sig, relatedTargetPP.sig))
          sub = cache[sig].pinned
          if tgtPtr in sub:
            afound = sub[sub.index(tgtPtr)]
            found = afound.pinnedPointer
            log.info('Found %d pointed struct in %s'%(sub.count(tgtPtr), sig))
            log.info('   source pp was  %s'%(pp))
            log.info('   source target pp was  %s'%(targetPP))
            for myrelatedPP in relatedPPs:
              log.info('   source related pp was  %s'%(myrelatedPP))
            for mytargetPPrelated in relatedTargetPPs:
              log.info("   source's target's related pp was  %s"%(mytargetPPrelated)) 
            log.info('   got %s'%( found))
            ok = True
            break
          elif tgtPtr in cache[sig].pinned_lightly:
            sub = cache[sig].pinned_lightly
            found = sub[sub.index(tgtPtr)].pinnedPointer
            log.info('Found a pointed struct in LIGHLY %s. was looking for %s , got %s'%(sig, relatedTargetPPs[0], found))
            ok = True
            break
        if not ok:
            log.info('This one does not points anywhere to a common pinnedPointer struct  %s'%(sig))
            ok = False
            break
        
  

class Dummy(object):
  pass

class AnonymousStructRange:
  def __init__(self,pinnedPointer):
    self.pinnedPointer = pinnedPointer
    self.start = pinnedPointer.getAddress()
    self.stop = pinnedPointer.getAddress(len(pinnedPointer))
    self.pointers = None 
    self.pointersValues = None 
    
  def getPointersAddr(self):
    if self.pointers is None:
      self.pointers = [self.pinnedPointer.getAddress(i) for i in range(0,len(self.pinnedPointer) ) ]
    return self.pointers

  def getPointersValues(self):
    if self.pointers is None:
      self.pointersValues = [self.pinnedPointer.sig.dump.readWord(self.pinnedPointer.getAddress(i)) for i in range(0,len(self.pinnedPointer) ) ]
    return self.pointersValues
  
  def __contains__(self,other):
    if isinstance(other, numbers.Number):
      rel = other - self.start
      if rel > len(self) or ( rel < 0 ):
        return False
      return True
    else:
      return False
  def __cmp__(self, other):
    if other in self:
      return 0
    else:
      return cmp(self.start, other)
  def __len__(self):
    return int(self.stop-self.start)


def t(mapper):

  for k,v in mapper.cacheValues2.items():
    # we have a list of x pp
    if len(v) == len(mapper.signatures):
      # we should have all 3 signatures
      found = [pp.sig for pp in v ]
      for s in mapper.signatures:
        if s not in [found]:
          print '%s not in found'%(s) 
      

def cacheExists(name):
  return os.access(os.path.sep.join([OUTPUTDIR,name]),os.F_OK)
  
def cacheLoad(name):
  log.debug('use cache for %s'%(name))
  return pickle.load(file(os.path.sep.join([OUTPUTDIR,name]),'r'))

def cacheToDisk(obj, name):
  log.debug('save to cache for %s'%(name))
  pickle.dump(obj, file(os.path.sep.join([OUTPUTDIR,name]),'w'))

  
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
  rootparser.add_argument('dumpfiles', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.', nargs='*')
  #rootparser.add_argument('dumpfile2', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('dumpfile3', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
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
