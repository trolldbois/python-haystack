#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import logging
import numpy
import os
import pickle
import shelve
import struct 
import sys
import time

from haystack.config import Config
from haystack.utils import Dummy
from haystack import dump_loader
from haystack import argparse_utils

import structure
import fieldtypes
import utils
import libc

log = logging.getLogger('reversers')


class ReverserContext():
  #dummy
  def __init__(self, mappings, heap):
    self.mappings = mappings
    # meta
    self.dumpname = mappings.name
    self.heap = heap
    self._init()
    return
    
  def _init(self):
    self.heapPathname= self.heap.pathname
    self.base = self.heap.start
    self.size = len(self.heap)
    # content
    self.structures = { } 
    #self.structures_addresses = numpy.array([],int)
    self.lastReversedStructureAddr = self.base # save our last state

    self.pointersMeta = Dummy()
    self.typesMeta = Dummy()
    
    self.resolved = False # True if all fields have been checked
    self.pointerResolved = False # True if all pointer fields have been checked

    self.parsed = set()
    
    self._init2()
    return

  def _init2(self):
    log.info('[+] Fetching cached structures addresses list')
    ptr_values, ptr_offsets, aligned_ptr, not_aligned_ptr = utils.getHeapPointers(self.dumpname, self.mappings)
    self.pointers_addresses = aligned_ptr
    self.pointers_offsets = ptr_offsets # need 

    log.info('[+] Fetching cached malloc chunks list')
    self.malloc_addresses, self.malloc_sizes = utils.getAllocations(self.dumpname, self.mappings, self.heap)
    
    # TODO switched
    if True: # malloc reverser
      self.structures_addresses = self.malloc_addresses
    else:
      self.structures_addresses = self.pointers_addresses # false
        
    log.info('[+] Fetching cached structures list')
    self.structures = dict([ (vaddr,s) for vaddr,s in structure.cacheLoadAllLazy(self) ])
    log.info('[+] Fetched %d cached structures addresses from disk'%( len(self.structures) ))

    if len(self.structures) == 0: # no structures yet, make them from MallocReverser
      log.info('[+] No cached structures - making them from malloc reversers')
      mallocRev = MallocReverser()
      context = mallocRev.reverse(self)
      mallocRev.check_inuse(self)
      log.info('[+] Built %d structures from malloc blocs'%( len(self.structures) ))
    
    return
  
  @classmethod
  def cacheLoad(cls, mappings):
    dumpname = os.path.normpath(mappings.name)
    context_cache = Config.getCacheFilename(Config.CACHE_CONTEXT, dumpname)
    context = pickle.load(file(context_cache,'r'))
    log.info('\t[-] loaded my context fromcache, Mapping heap to mem')
    context.mappings = mappings
    context.heap = context.mappings.getHeap()
    log.info('\t[-] loaded heap')
    
    context._init2()
    return context
    
  
  def save(self):
    # we only need dumpfilename to reload mappings, addresses to reload cached structures
    context_cache = Config.getCacheFilename(Config.CACHE_CONTEXT, self.dumpname)
    pickle.dump(self, file(context_cache,'w'))
    #d = shelve.open(context_cache)
    #d['context'] = self
    #d.close()
  
  def __getstate__(self):
    d = self.__dict__.copy()
    del d['mappings']
    del d['heap']
    del d['structures']
    del d['structures_addresses']
    del d['pointers_addresses']
    del d['pointers_offsets']
    del d['malloc_addresses']
    del d['malloc_sizes']
    #d['dumpname'] = os.path.normpath(self.dumpname )
    #d['heapPathname']= self.heap.pathname
    #d['structures_addresses'] = self.structures_addresses
    #d['lastReversedStructureAddr'] = self.lastReversedStructureAddr
    return d

  def __setstate__(self, d):
    self.__dict__ = d
    #self.mappings = dump_loader.load( self.dumpname, lazy=True)  
    #self.heap = self.mappings.getMmap(d['heapPathname'])
    self.structures = { } 
    self.structures_addresses = numpy.array([],int)
    #self._init()
    #self.structures_addresses = d['structures_addresses'] # load from int_array its quicker
    #self.lastReversedStructureAddr = d['lastReversedStructureAddr']
    #load structures from cache
    #self.structures = dict([ (vaddr,s) for vaddr,s in structure.cacheLoadAllLazy(self.dumpname,self.structures_addresses)])
    #self.structures = {}
    #self.parsed = d['parsed']

    return
  



''' 
Inherits this class when you are delivering a controller that target structure-based elements and :
  * check consistency between structures,
  * aggregate structures based on a heuristic,
'''
class StructureOrientedReverser():
  '''
    Apply heuristics on context.heap
  '''
  def __init__(self):
    self.cacheFilenames=[]
    #self.cacheDict
  
  ''' Improve the reversing process
  '''
  def reverse(self, ctx, cacheEnabled=True):
    skip = False
    if cacheEnabled:
      ctx,skip = self._getCache(ctx)
    try:
      if skip:
        log.info('[+] skipping %s - cached results'%(str(self)))
      else:
        # call the heuristic
        self._reverse(ctx)
    except EOFError,e: # error while unpickling
      log.error('incomplete unpickling : %s - You should probably reset context.parsed'%(e))
      ###context.parsed = set()
      import sys
      ex = sys.exc_info()
      raise ex[1], None, ex[2]
    finally:
      if cacheEnabled:
        self._putCache(ctx)
    return ctx
  
  ''' Subclass implementation of the reversing process '''
  def _reverse(self, ctx, addrs=None):
    raise NotImplementedError

  def _getCache(self, ctx):
    ''' define cache read on your input/output data '''
    # you should check timestamp against cache
    if str(self) in ctx.parsed :
      return ctx, True
    return ctx, False

  def _putCache(self, ctx):
    ''' define cache write on your output data '''
    t0 = time.time()
    log.info('\t[-] please wait while I am saving the context')
    # save context with cache
    ctx.save()
    return 

  def _saveStructures(self, ctx):
    tl = time.time()
    # dump all structures
    for i,s in enumerate(ctx.structures.values()):
      #  print s.dirty
      try:
        s.saveme(ctx)
      except KeyboardInterrupt,e:
        os.remove(s.fname)
        raise e
      if time.time()-tl > 30: #i>0 and i%10000 == 0:
        t0 = time.time()
        log.info('\t\t - %2.2f secondes to go '%( (len(ctx.structures)-i)*((tl-t0)/i) ) )
        tl = t0
    tf = time.time()
    log.info('\t[.] saved in %2.2f secs'%(tf-tl))
    return
      
  def __str__(self):
    return '<%s>'%(self.__class__.__name__)


'''
  Looks at malloc's malloc_chunk .
'''
class MallocReverser(StructureOrientedReverser):
  ''' 
  slice the mapping in several structures delimited per malloc_chunk-boundaries
  '''
  def _reverse(self, context):
    log.info('[+] Reversing malloc_chunk in %s'%(context.heap))
        
    ## we really should be lazyloading structs..
    t0 = time.time()
    tl = t0
    loaded = 0
    prevLoaded = 0
    unused = 0
    lengths = context.malloc_sizes
    todo = sorted(set(context.structures_addresses) - set(context.structures.keys()))
    fromcache = len(context.structures_addresses) - len(todo)
    offsets = list(context.pointers_offsets)
    # build structs from pointers boundaries. and creates pointer fields if possible.
    log.info('[+] Adding new raw structures from malloc_chunks contents - %d todo'%(len(todo)))
    for i, ptr_value in enumerate(context.structures_addresses):
      if ptr_value in context.structures.keys():
        continue
      loaded += 1
      size = lengths[i]
      # save the ref/struct type
      chunk_addr = ptr_value-2*Config.WORDSIZE
      mc1 = context.heap.readStruct(chunk_addr, libc.ctypes_malloc.malloc_chunk)
      if mc1.check_inuse(context.mappings, chunk_addr):
        mystruct = structure.makeStructure(context, ptr_value, size)
        context.structures[ ptr_value ] = mystruct
        # add pointerFields
        offsets, my_pointers_addrs = utils.dequeue(offsets, ptr_value, ptr_value+size)
        log.debug('Adding %d pointer fields field on struct of size %d'%( len(my_pointers_addrs), size) )
        # optimise insertion
        if len(my_pointers_addrs) > 0:
          mystruct.addFields(my_pointers_addrs, fieldtypes.FieldType.POINTER, Config.WORDSIZE, False)
        #cache to disk
        mystruct.saveme(context)
      # next
      if time.time()-tl > 10: #i>0 and i%10000 == 0:
        tl = time.time()
        rate = ((tl-t0)/(loaded)) if loaded else ((tl-t0)/(loaded+fromcache)) #DEBUG...
        log.info('%2.2f secondes to go (b:%d/c:%d)'%( (len(todo)-i)*rate, loaded, fromcache ) )
    log.info('[+] Extracted %d structures in %2.0f (b:%d/c:%d/u:%d)'%(loaded+ fromcache, time.time()-t0,loaded, fromcache, unused ) )
    
    context.parsed.add(str(self))
    return

  def check_inuse(self, context):
    import libc.ctypes_malloc
    chunks = context.malloc_addresses
    pointers = context.pointers_addresses
    unused = set(chunks) - set(pointers)
    heap = context.heap
    used=0
    for m1 in unused:
      mc1 = heap.readStruct(m1-8, libc.ctypes_malloc.malloc_chunk)
      if mc1.check_inuse(context.mappings, m1-8):
        used+=1
    log.info('[+] Found %s allocs used by not referenced by pointers'%(used))
    return 
    
'''
  Looks at pointers values to build basic structures boundaries.
'''
class PointerReverser(StructureOrientedReverser):
  ''' 
  slice the mapping in several structures delimited per pointer-boundaries
  '''
  def _reverse(self, context):
    log.info('[+] Reversing pointers in %s'%(context.heap))
    
    # make structure lengths from interval between pointers
    lengths = self.makeLengths(context.heap, context.structures_addresses)    
    
    ## we really should be lazyloading structs..
    t0 = time.time()
    tl = t0
    loaded = 0
    todo = sorted(set(context.structures_addresses) - set(context.structures.keys()))
    fromcache = len(context.structures_addresses) - len(todo)
    # build structs from pointers boundaries. and creates pointer fields if possible.
    log.info('[+] Adding new raw structures from pointers boundaries')
    offsets = list(context.pointers_offsets)
    for i, ptr_value in enumerate(context.structures_addresses):
      # toh stoupid
      if ptr_value in todo:
        loaded+=1
        size = lengths[i]
        # get offset of pointer fields
        offsets, my_pointers_addrs = utils.dequeue(offsets, ptr_value, ptr_value+size)
        # save the ref/struct type
        mystruct = structure.makeStructure(context, ptr_value, size)
        context.structures[ ptr_value ] = mystruct
        #mystruct.save()
        # get pointers addrs in start -> start+size
        log.debug('Adding %d pointer fields field '%( len(my_pointers_addrs)) )
        for p_addr in my_pointers_addrs:
          f = mystruct.addField(p_addr, fieldtypes.FieldType.POINTER, Config.WORDSIZE, False)
          #log.debug('Add field at %lx offset:%d'%( p_addr,p_addr-ptr_value))

      if time.time()-tl > 10: #i>0 and i%10000 == 0:
        tl = time.time()
        rate = ((tl-t0)/(loaded)) if loaded else ((tl-t0)/(loaded+fromcache)) #DEBUG...
        log.info('%2.2f secondes to go (b:%d/c:%d)'%( (len(todo)-i)*rate, loaded, fromcache ) )
    log.info('[+] Extracted %d structures in %2.0f (b:%d/c:%d)'%(loaded+ fromcache, time.time()-t0,loaded, fromcache ) )
    
    context.parsed.add(str(self))
    return

  def makeLengths(self, heap, aligned):
    lengths=[(aligned[i+1]-aligned[i]) for i in range(len(aligned)-1)]    
    lengths.append(heap.end-aligned[-1]) # add tail
    return lengths

'''
  Decode each structure by asserting simple basic types from the byte content.
'''
class FieldReverser(StructureOrientedReverser):
  
  def _reverse(self, context):

    log.info('[+] FieldReverser: decoding fields')
    t0 = time.time()
    tl = t0
    decoded = 0
    fromcache = 0
    ## writing to file
    fout = file(Config.getCacheFilename(Config.CACHE_GENERATED_PY_HEADERS_VALUES, context.dumpname),'w')
    towrite=[]
    #for ptr_value,anon in context.structures.items():
    for ptr_value in sorted(context.structures.keys(), reverse=True): # lets try reverse
      anon = context.structures[ptr_value]
      if anon.isResolved(): # TODO this is a performance hit, unproxying...
        fromcache+=1
      else:
        decoded+=1
        anon.decodeFields()
        anon.saveme(context)
      ## output headers
      towrite.append(anon.toString())
      if time.time()-tl > 30: #i>0 and i%10000 == 0:
        tl = time.time()
        rate = ((tl-t0)/(decoded+fromcache)) if decoded else ((tl-t0)/(fromcache))
        log.info('%2.2f secondes to go (d:%d,c:%d)'%( 
            (len(context.structures)-(fromcache+decoded))*rate, decoded,fromcache ) )
        fout.write('\n'.join(towrite) )
        towrite=[]
    
    log.info('[+] FieldReverser: finished %d structures in %2.0f (d:%d,c:%d)'%(fromcache+decoded, time.time()-t0, decoded,fromcache ) )
    context.parsed.add(str(self))
    return

'''
  Identify pointer fields and their target structure.
'''
class PointerFieldReverser(StructureOrientedReverser):
  
  def _reverse(self, context):
    log.info('[+] PointerFieldReverser: resolving pointers')
    t0 = time.time()
    tl = t0
    decoded = 0
    fromcache = 0
    for ptr_value in sorted(context.structures.keys(), reverse=True): # lets try reverse
      anon = context.structures[ptr_value]
      if anon.isPointerResolved():
        fromcache+=1
      else:
        decoded+=1
        #if not hasattr(anon, 'mappings'):
        #  log.error('damned, no mappings in %x'%(ptr_value))
        #  anon.mappings = context.mappings
        anon.resolvePointers(context.structures_addresses, context.structures)
        anon.saveme(context)
      if time.time()-tl > 30: 
        tl = time.time()
        rate = ((tl-t0)/(1+decoded+fromcache)) if decoded else ((tl-t0)/(1+fromcache))
        log.info('%2.2f secondes to go (d:%d,c:%d)'%( 
            (len(context.structures)-(fromcache+decoded))*rate, decoded,fromcache ) )
    log.info('[+] PointerFieldReverser: finished %d structures in %2.0f (d:%d,c:%d)'%(fromcache+decoded, time.time()-t0, decoded,fromcache ) )
    context.parsed.add(str(self))
    return

'''
  Identify double Linked list. ( list, vector, ... )
'''
class DoubleLinkedListReverser(StructureOrientedReverser):
  
  def _reverse(self, context):
    log.info('[+] DoubleLinkedListReverser: resolving first two pointers for %d'%( len(context.structures) ))
    t0 = time.time()
    tl = t0
    done = 0
    found = 0
    members = set()
    lists = []
    for ptr_value in sorted(context.structures.keys()):
      #self.pointers_addresses = aligned_ptr
      #self.pointers_offsets = ptr_offsets # need 
      '''for i in range(1, len(context.pointers_offsets)): # find two consecutive ptr
      if context.pointers_offsets[i-1]+Config.WORDSIZE != context.pointers_offsets[i]:
        done+=1
        continue
      ptr_value = context.pointers_addresses[i-1]
      if ptr_value not in context.structures_addresses:
        done+=1
        continue # if not head of structure, not a classic DoubleLinkedList ( TODO, think kernel ctypes + offset)
      '''
      #anon = context.structures[ptr_value]
      if ptr_value in members:
        continue # already checked
      if ( self.isLinkedListMember(context, ptr_value)):
        head, _members = self.iterateList(context, ptr_value)
        if _members is not None:
          print 'head', hex(head), 'members',
          for m in _members:
            print hex(m),
          print
          members.update(_members)
          done+=len(_members)-1
          lists.append( (head,_members) ) # save list chain
          # set names
          context.structures[head].setName('list_head')
          [context.structures[m].setName('list_%x_%d'%(head,i)) for i,m in enumerate(_members)]
          #TODO get substructures ( P4P4xx ) signature and 
          # a) extract substructures
          # b) group by signature
          found +=1
      done+=1
      if time.time()-tl > 30: 
          tl = time.time()
          rate = ((tl-t0)/(1+done))
          #log.info('%2.2f secondes to go (d:%d,f:%d)'%( (len(context.structures)-done)*rate, done, found))
          log.info('%2.2f secondes to go (d:%d,f:%d)'%( (len(context.pointers_offsets)-done)*rate, done, found))
    log.info('[+] DoubleLinkedListReverser: finished %d structures in %2.0f (f:%d)'%(done, time.time()-t0, found ) )
    context.parsed.add(str(self))
    #
    context.lists = lists
    return

  def twoWords(self, ctx, st_addr, offset=0):
    return ctx.heap.getByteBuffer()[st_addr-ctx.heap.start+offset:st_addr-ctx.heap.start+offset+2*Config.WORDSIZE]
  
  def isLinkedListMember(self, context, ptr_value):
    f1,f2 = struct.unpack('LL', self.twoWords(context, ptr_value ) )
    # get next and prev
    if (f1 in context.heap) and (f2 in context.heap):
      st1_f1,st1_f2 = struct.unpack('LL', self.twoWords(context, f1 ) )
      st2_f1,st2_f2 = struct.unpack('LL', self.twoWords(context, f2 ))
      # check if the three pointer work
      if ( (ptr_value == st1_f2 == st2_f1 ) or
           (ptr_value == st2_f2 == st1_f1 ) ):
        #log.debug('%x is part of a double linked-list'%(ptr_value))
        if (f1 in context.structures_addresses ) and (f2 in context.structures_addresses ): 
          return True
        else:
          #log.debug('FP Bad candidate not head of struct: %x '%(ptr_value))
          return False
    return False
      
  def iterateList(self, context, head_addr):
    members = []
    members.append(head_addr)
    f1,f2 = struct.unpack('LL', self.twoWords(context, head_addr ))
    if (f1 == head_addr):
      log.debug('f1 is head_addr too')
    if (f2 == head_addr):
      log.debug('f2 is head_addr too')
      
    current = head_addr
    while (f1 in context.structures_addresses ):
      if f1 in members:
        log.debug('loop to head - returning %d members from head.addr %x f1:%x'%(len(members)-1, head_addr, f1))
        return self.findHead(context, members)
      first_f1,first_f2 = struct.unpack('LL', self.twoWords(context, f1 ))
      if ( current == first_f2 ) :
        members.append(f1)
        current = f1
        f1 = first_f1
      else:
        log.warning('(st:%x f1:%x) f2:%x is not current.addr:%x'%(current, first_f1, first_f2, current))
        return None, None
        
    # if you leave the while, you are out of the heap address space. That is probably not a linked list...
    return None, None

  def findHead(self, ctx, members):
    sizes = [(ctx.malloc_sizes[ctx.structures_addresses.index(m)], m) for m in members]
    sizes.sort()
    if sizes[0]<3*Config.WORDSIZE:
      log.error('a double linked list element must be 3 WORD at least')
      raise ValueError('a double linked list element must be 3 WORD at least')
    numWordSized = [s for s,addr in sizes].count(3*Config.WORDSIZE)
    if numWordSized == 1:
      head = sizes.pop(0)[1]
    else: #if numWordSized > 1:
      ## find one element with 0, and take that for granted...
      head = None
      for s, addr in sizes:
        if s == 3*Config.WORDSIZE:
          # read ->next ptr and first field of struct || null
          f2, field0 = struct.unpack('LL', self.twoWords(ctx, addr+Config.WORDSIZE ) )
          if field0 == 0: # this could be HEAD. or a 0 value.
            head = addr
            log.debug('We had to guess the HEAD for this linked list %x'%(addr))
            break
      if head == None:
        head = sizes[0][1]
        #raise TypeError('No NULL pointer/HEAD in the double linked list')
        log.warning('No NULL pointer/HEAD in the double linked list - head is now %x'%(head))
    return (head,[m for (s,m) in sizes])

'''
  use the pointer relation between structure to map a graph.
'''
class PointerGraphReverser(StructureOrientedReverser):
  
  def _reverse(self, context):
    import networkx
    #import code
    #code.interact(local=locals())
    graph = networkx.DiGraph()
    graph.add_nodes_from([ '%x'%k for k in context.structures.keys()]) # we only need the addresses...
    log.info('[+] Graph - added %d nodes'%(graph.number_of_nodes()))
    t0 = time.time()
    tl = t0
    for i, item in enumerate(sorted(context.structures.items())):
      ptr_value, struct = item
      targets = set(( '%x'%ptr_value, '%x'%child.target_struct_addr ) for child in struct.getPointerFields()) #target_struct_addr
      ## DEBUG
      if len(struct.getPointerFields()) >0:
        if len(targets) == 0:
          raise ValueError
      ## DEBUG
      graph.add_edges_from( targets )
      if time.time()-tl > 30: 
        tl = time.time()
        rate = ((tl-t0)/(i)) #if decoded else ((tl-t0)/(fromcache))
        log.info('%2.2f secondes to go (g:%d)'%( 
            (len(context.structures)-(i))*rate, i ) )
    log.info('[+] Graph - added %d edges'%(graph.number_of_edges()))
    networkx.readwrite.gexf.write_gexf( graph, Config.getCacheFilename(Config.CACHE_GRAPH, context.dumpname))
    context.parsed.add(str(self))
    return


def refreshOne(context, ptr_value):
  aligned=context.structures_addresses
  
  lengths=[(aligned[i+1]-aligned[i]) for i in range(len(aligned)-1)]    
  lengths.append(context.heap.end-aligned[-1]) # add tail
  size = lengths[aligned.index(ptr_value)]

  offsets = list(context.pointers_offsets)
  offsets, my_pointers_addrs = utils.dequeue(offsets, ptr_value, ptr_value+size)
  # save the ref/struct type
  mystruct = structure.makeStructure(context, ptr_value, size)
  context.structures[ ptr_value ] = mystruct
  for p_addr in my_pointers_addrs:
    f = mystruct.addField(p_addr, fieldtypes.FieldType.POINTER, Config.WORDSIZE, False)
  #resolvePointers
  mystruct.resolvePointers(context.structures_addresses, context.structures)
  #resolvePointers
  return mystruct
  
def save_headers(context, addrs=None):
  ''' structs_addrs is sorted '''
  fout = file(Config.getCacheFilename(Config.CACHE_GENERATED_PY_HEADERS_VALUES, context.dumpname),'w')
  towrite = []
  if addrs is None:
    addrs = iter(context.structures.keys())

  for vaddr in addrs:
    anon = context.structures[vaddr]
    towrite.append(anon.toString())
    if len(towrite) >= 10000:
      try:
        fout.write('\n'.join(towrite) )
      except UnicodeDecodeError, e:
        print 'ERROR on ',anon
      towrite = []
      fout.flush()
  fout.write('\n'.join(towrite) )
  fout.close()
  return


def getContext(fname):
  mappings = dump_loader.load( fname)  
  try:
    context = ReverserContext.cacheLoad(mappings)
  except IOError,e:
    context = ReverserContext(mappings, mappings.getHeap())  
  return context

def search(opts):
  #
  log.info('[+] Loading the memory dump ')
  try:
    context = getContext(opts.dumpname)
    if not os.access(Config.getStructsCacheDir(context.dumpname), os.F_OK):    
      os.mkdir(Config.getStructsCacheDir(context.dumpname))

    mallocRev = MallocReverser()
    context = mallocRev.reverse(context)
    mallocRev.check_inuse(context)
    ## find basic boundaries
    #ptrRev = PointerReverser()
    #context = ptrRev.reverse(context)

    doublelink = DoubleLinkedListReverser()
    context = doublelink.reverse(context, False)
    log.info('[+] saving linkedlist headers')
    vaddrs = [ addr for (head, list1) in context.lists for addr in list1 ]
    save_headers(context, vaddrs)
    #fr._saveStructures(context.lists)
    
    return 
    # decode bytes contents to find basic types.
    # DEBUG reactivate, 
    fr = FieldReverser()
    context = fr.reverse(context)

    # identify pointer relation between structures
    pfr = PointerFieldReverser()
    context = pfr.reverse(context)

    # graph pointer relations between structures
    ptrgraph = PointerGraphReverser()
    context = ptrgraph.reverse(context)
    ptrgraph._saveStructures(context)
        
    

    log.info('[+] saving headers')
    save_headers(context)
    fr._saveStructures(context)
    ##libRev = KnowStructReverser('libQt')
    ##context = libRev.reverse(context)
    # we have more enriched context
    
    
    # etc
  except KeyboardInterrupt,e:
    #except IOError,e:
    log.warning(e)
    log.info('[+] %d structs extracted'%(  len(context.structures)) )
    raise e
    pass
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-reversers', description='Do a iterative pointer search to find structure.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('dumpname', type=argparse_utils.readable, action='store', help='Source memory dump by haystack.')
  rootparser.set_defaults(func=search)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)

  level=logging.INFO
  if opts.debug :
    level=logging.DEBUG
  #ad16c58
  flog = os.path.sep.join([Config.cacheDir,'log'])
  logging.basicConfig(level=level, filename=flog, filemode='w')
  
  #logging.getLogger('haystack').setLevel(logging.INFO)
  #logging.getLogger('dumper').setLevel(logging.INFO)
  #logging.getLogger('structure').setLevel(logging.INFO)
  #logging.getLogger('field').setLevel(logging.INFO)
  #logging.getLogger('progressive').setLevel(logging.INFO)
  logging.getLogger('reversers').addHandler(logging.StreamHandler(stream=sys.stdout))

  log.info('[+] output log to %s'% flog)

  opts.func(opts)


if __name__ == '__main__':
  main(sys.argv[1:])
