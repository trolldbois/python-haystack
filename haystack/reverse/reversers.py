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
import sys

from haystack.config import Config
from haystack.utils import Dummy
from haystack import memory_dumper

import structure
import fieldtypes
import utils

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
    self.base = self.heap.start
    self.size = len(self.heap)
    # content
    ##self.bytes = self.heap.readBytes(self.base, self.size)
    self.structures = { } #self.base: structure.makeStructure(self, self.base, self.size) } # one big fat structure
    self.structures_addresses = numpy.array([],int)
    self.lastReversedStructureAddr = self.base # save our last state

    self.pointersMeta = Dummy()
    self.typesMeta = Dummy()
    
    self.resolved = False # True if all fields have been checked
    self.pointerResolved = False # True if all pointer fields have been checked
    
    return
  
  @classmethod
  def cacheLoad(cls, dumpname):
    context_cache = Config.getCacheFilename(Config.CACHE_CONTEXT, dumpname)
    return pickle.load(file(context_cache,'r'))
    #if not os.access(context_cache,os.F_OK):
    #  raise IOError('file not found') 
    #d = shelve.open(context_cache)
    #me = d['context']
    #d.close()
    #return me
    
  
  def save(self):
    # we only need dumpfilename to reload mappings, addresses to reload cached structures
    context_cache = Config.getCacheFilename(Config.CACHE_CONTEXT, self.dumpname)
    pickle.dump(self, file(context_cache,'w'))
    #d = shelve.open(context_cache)
    #d['context'] = self
    #d.close()
  
  def __getstate__(self):
    d = {}
    d['dumpname'] = self.dumpname 
    d['heapPathname']= self.heap.pathname
    d['structures_addresses'] = self.structures_addresses
    d['lastReversedStructureAddr'] = self.lastReversedStructureAddr
    return d

  def __setstate__(self, d):
    self.dumpname = d['dumpname']
    self.mappings = memory_dumper.load( file(self.dumpname), lazy=True)  
    self.heap = self.mappings.getMmap(d['heapPathname'])
    self._init()
    self.structures_addresses = d['structures_addresses']
    self.lastReversedStructureAddr = d['lastReversedStructureAddr']
    #load structures from cache
    self.structures = dict([ (vaddr,s) for vaddr,s in structure.cacheLoadAll(self.dumpname,self.structures_addresses)])
    return self
  

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
    if cacheEnabled:
      ctx = self._getCache(ctx)
    try:
      # call the heuristic
      self._reverse(ctx)
    finally:
      if cacheEnabled:
        self._putCache(ctx)
    return ctx
  
  ''' Subclass implementation of the reversing process '''
  def _reverse(self, ctx):
    raise NotImplementedError

  def _checkCache(self, ctx):
    for filename in cacheFilenames:
      if not os.access(filename, os.F_OK):
        return False
    return True


  def _getCache(self, ctx):
    ''' define cache read on your input/output data '''
    try:
      ctx2 = ReverserContext.cacheLoad(ctx.dumpname)
    except IOError,e:
      return ctx
    # you should check timestamp against cache
    ##raise NotImplementedError
    return ctx2

  def _putCache(self, ctx):
    ''' define cache write on your output data '''
    #raise NotImplementedError
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
    ptr_values, ptr_offsets, aligned_ptr, not_aligned_ptr = utils.getHeapPointers(context.dumpname, context.mappings)
    
    # make structure lengths from interval between pointers
    lengths = self.makeLengths(context.heap, aligned_ptr)
    
    # this is the list of build anon struct. it will grow towards aligned_ptr...
    # tis is the optimised key list of structCache
    #context.structures_addresses = numpy.array([],int)
      
    nbMembers = 0
    # build structs from pointers boundaries. and creates pointer fields if possible.
    for i, ptr_value in enumerate(aligned_ptr):
      if ptr_value not in context.structures:
        size = lengths[i]
        # save the ref/struct type
        context.structures[ ptr_value ] = structure.makeStructure(context, ptr_value, size)
        context.structures_addresses = numpy.append(context.structures_addresses, ptr_value)
      else:
        log.info('loaded %x from cache'%(ptr_value))
      if i%100 == 0:
        log.info('\t[-] at structures %d'%(i))
        self._putCache(context)
    log.info('Extracted %d structures'%(len(context.structures_addresses)) )
    return



  def makeLengths(self, heap, aligned):
    lengths=[(aligned[i+1]-aligned[i]) for i in range(len(aligned)-1)]    
    lengths.append(heap.end-aligned[-1]) # add tail
    return lengths


  def _putCache(self, ctx):
    ''' define cache write on your output data '''
    # save context with cache
    ctx.save()
    # dump all structures
    for s in ctx.structures.values():
      s.save()
    # save mem2py headers file
    save_headers(ctx)
    return 



class FieldReverser():
  def reverse(self, context):
    # make destroyable copies
    aligned = list(aligned_ptr)
    addrs = list(ptr_offsets) # list of pointers, some of them are not in heap
    unaligned = list(not_aligned_ptr)

    nbMembers = 0
    # build structs from pointers boundaries. and creates pointer fields if possible.
    for i, ptr_value in enumerate(aligned):
      # identify pointer fields
      addrs, my_pointers_addrs = utils.dequeue(addrs, ptr_value, ptr_value+size)  

      log.debug('Created a struct with %d pointers fields'%( len(my_pointers_addrs) ))
      # get pointers found at offset addrs in start -> start+size
      for p_addr in my_pointers_addrs:
        f = anon.addField(p_addr, FieldType.POINTER, Config.WORDSIZE, False)
        log.debug('Add field at %lx offset:%d'%( p_addr,p_addr-start))

      # the other pointers values, that are not aligned
      unaligned, my_unaligned_addrs = utils.dequeue(unaligned, ptr_value, ptr_value+size)
      ## set field for unaligned pointers, that sometimes gives good results ( char[][] )
      for p_addr in my_unaligned_addrs:
        log.debug('Guess field at %lx offset:%d'%( p_addr,p_addr-start))
        if anon.guessField(p_addr) is not None: #, FieldType.UKNOWN):
          nbMembers+=1
          hasMembers=True
        # not added
      # try to decode fields
      log.debug('build: decoding fields')
      anon.decodeFields()



def save_headers(context):
  ''' structs_addrs is sorted '''
  fout = file(Config.getCacheFilename(Config.CACHE_GENERATED_PY_HEADERS_VALUES, context.dumpname),'w')
  towrite = []
  for vaddr,anon in context.structures.items():
    towrite.append(anon.toString())
    if len(towrite) >= 10000:
      fout.write('\n'.join(towrite) )
      towrite = []
  fout.write('\n'.join(towrite) )
  fout.close()
  return

def search(opts):
  #
  mappings = memory_dumper.load( opts.dumpfile, lazy=True)  
  context = ReverserContext(mappings, mappings.getHeap())  
  try:
    ptrRev = PointerReverser()
    context = ptrRev.reverse(context)
    # we have enriched context
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
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
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
