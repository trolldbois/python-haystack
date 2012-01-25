#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Old poc code integrated in reversers. """

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import argparse
import os
import time
import sys
import numpy

from haystack.config import Config
from haystack import dump_loader

from fieldtypes import FieldType
import signature 
import structure
import utils


log = logging.getLogger('progressive')

DEBUG_ADDRS=[]


# a 12 Mo heap takes 30 minutes on my slow notebook
# what is \xb2 padding for ?
# huge bug with zerroes fields aggregation
# the empty space at the end of the heap is making the reverse quite slow.... logs outputs line rate 10/sec againt 2k/sec

# TODO look for VFT and malloc metadata ?
# se stdc++ to unmangle c++
# vivisect ?
# TODO 1: make an interactive thread on that anon_struct and a struct Comparator to find similar struct.
#         that is a first step towards structure identification && naming. + caching of info
#      2: dump ctypes structure into python file + cache (vaddr, Structurectypes ) to pickle file ( reloading/continue possible with less recalculation )
# create a typename for \xff * 8/16. buffer color ? array of char?

# Compare sruct type from parent with multiple pointer (


def make(opts):
  log.info('[+] Extracting structures from pointer values and offsets.')
  ## get the list of pointers values pointing to heap
  ## need cache
  mappings = dump_loader.load( opts.dumpfile, lazy=True)  
  values,heap_addrs, aligned, not_aligned = utils.getHeapPointers(opts.dumpfile.name, mappings)
  dumpname = opts.dumpfile.name
  # we
  if not os.access(Config.structsCacheDir, os.F_OK):
    os.mkdir(Config.structsCacheDir )
  heap = mappings.getHeap()
  log.info('[+] Reversing %s'%(heap))
  # creates
  t0 = time.time()
  structCache = {}
  signatures = {}
  lastNb=0
  for anon_struct, structs_addrs in buildAnonymousStructs(mappings, heap, aligned, 
                                not_aligned, heap_addrs, structCache, reverse=False): # reverse is way too slow...
    #
    # regexp could be better if crossed against another dump.
    anon_struct.save()
    # save signature
    cacheSignature(signatures, anon_struct)
    #
    nb = len(structs_addrs)
    if nb >= lastNb+1000: #time.time() - t0 > 30 :
      td = time.time()
      log.info('\t[-] extracted @%lx, %lx left - %d structs extracted (%d)'%(anon_struct.vaddr, 
                                              heap.end-anon_struct.vaddr, len(structCache), td-t0))
      rewrite(structs_addrs, structCache, dumpname)
      saveSignatures(signatures, structCache, dumpname)
      log.info('\t\t[.] %2.2f secs to rewrite %d structs'%(time.time()-td, len(structs_addrs)))
      t0 = time.time()
      lastNb = nb
    Config.nbAnonymousStruct = nb
    pass
  # final pass
  rewrite(structs_addrs, structCache, dumpname)  
  saveSignatures(signatures, structCache)
  ## we have :
  ##  resolved PinnedPointers on all sigs in ppMapper.resolved
  ##  unresolved PP in ppMapper.unresolved
  
  ## next step
  log.info('Pin resolved PinnedPointers to their respective heap.')

def cacheSignature(cache, struct):
  sig = struct.getSignature(text=True)
  if sig not in cache:
    cache[sig]=[]
  cache[sig].append(struct)
  return

def buildAnonymousStructs(mappings, heap, _aligned, not_aligned, p_addrs, structCache, reverse=False):
  ''' values: ALIGNED pointer values
  '''
  lengths=[]
  
  aligned = list(_aligned)
  for i in range(len(aligned)-1):
    lengths.append(aligned[i+1]-aligned[i])
  lengths.append(heap.end-aligned[-1]) # add tail
  
  addrs = list(p_addrs)
  unaligned = list(not_aligned)
  
  if reverse:
    aligned.reverse()
    lengths.reverse()
    addrs.reverse()
    unaligned.reverse()
    #dequeue=dequeue_reverse

  # this is the list of build anon struct. it will grow towards p_addrs...
  # tis is the optimised key list of structCache
  structs_addrs = numpy.array([])
    
  nbMembers = 0
  # make AnonymousStruct
  for i in range(len(aligned)):
    hasMembers=False
    start = aligned[i]
    size = lengths[i]
    ## debug
    if start in DEBUG_ADDRS:
      logging.getLogger('progressive').setLevel(logging.DEBUG)
    else:
      logging.getLogger('progressive').setLevel(logging.INFO)

    # the pointers field address/offset
    addrs, my_pointers_addrs = utils.dequeue(addrs, start, start+size)  ### this is not reverse-compatible
    # the pointers values, that are not aligned
    unaligned, my_unaligned_addrs = utils.dequeue(unaligned, start, start+size)
    ### read the struct
    anon = structure.AnonymousStructInstance(mappings, aligned[i], heap.readBytes(start, size) )
    #save the ref/struct type
    structCache[ anon.vaddr ] = anon
    structs_addrs = numpy.append(structs_addrs, anon.vaddr)
    log.debug('Created a struct with %d pointers fields'%( len(my_pointers_addrs) ))
    # get pointers addrs in start -> start+size
    for p_addr in my_pointers_addrs:
      f = anon.addField(p_addr, FieldType.POINTER, Config.WORDSIZE, False)
      log.debug('Add field at %lx offset:%d'%( p_addr,p_addr-start))
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
    # try to resolve pointers
    ##log.debug('build: resolve pointers')
    ##structs_addrs.sort()
    #what is the point ? most of them are not resolvable yet...
    ##anon.resolvePointers(structs_addrs, structCache)
    # debug
    if hasMembers:
      for _f in anon.fields:
        if _f.size == -1:
          log.debug('ERROR, %s '%(_f))
      log.debug('Created a struct %s with %d fields'%( anon, len(anon.fields) ))
      #log.debug(anon.toString())
    #
    yield (anon, structs_addrs)
  log.info('Typed %d stringfields'%(nbMembers))
  return



def rewrite(structs_addrs, structCache, dumpname):
  ''' structs_addrs is sorted '''
  structs_addrs.sort()
  fout = file(Config.getCacheFilename(Config.CACHE_GENERATED_PY_HEADERS_VALUES, dumpname),'w')
  towrite = []
  for vaddr in structs_addrs:
    ## debug
    if vaddr in DEBUG_ADDRS:
      logging.getLogger('progressive').setLevel(logging.DEBUG)
    else:
      logging.getLogger('progressive').setLevel(logging.INFO)
    anon = structCache[vaddr]
    anon.resolvePointers(structs_addrs, structCache)
    towrite.append(anon.toString())
    if len(towrite) >= 10000:
      fout.write('\n'.join(towrite) )
      towrite = []
  fout.write('\n'.join(towrite) )
  fout.close()
  return

def saveSignatures(cache, structCache, dumpname):
  ''' cache is {} of sig: [structs] '''
  fout = file(Config.getCacheFilename(Config.CACHE_GENERATED_PY_HEADERS,dumpname),'w')
  towrite = []
  tuples = [(len(structs), sig, structs) for sig,structs in cache.items() ]
  tuples.sort(reverse=True)
  for l, sig,structs in tuples:
    values=''
    s='''
# %d structs
#class %s
%s
'''%(len(structs), sig, structs[0].toString())
    fout.write(s)
  fout.close()

  

def statsMe():
  lines=[l for l in file('log','r').readlines() if 'extracted' in l]
  stats = [ (int(l.split(' ')[3],16), int(l.split(' ')[6]), int(l.split(' ')[9][1:-2]) ) for l in lines ]
  last = stats[0]
  for s in stats[1:]:
    bytes = last[0] - s[0]
    nb = s[1] - last[1]
    ts = s[2]
    print 'done %2.2f struct/secs %2.2f bytes/sec %d structs'%(nb/ts, bytes/ts, s[1] )
    last = s

def search(opts):
  #
  try:
    Config.nbAnonymousStruct = 0
    make(opts)
  except KeyboardInterrupt,e:
    #except IOError,e:
    log.warning(e)
    log.info('[+] %d structs extracted'%(  Config.nbAnonymousStruct) )
    raise e
    pass
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-progressive', description='Do a iterative pointer search to find structure.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('dumpfiles', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.', nargs='*')
  #rootparser.add_argument('dumpfile2', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('dumpfile3', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
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
  
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('dumper').setLevel(logging.INFO)
  logging.getLogger('structure').setLevel(logging.INFO)
  logging.getLogger('field').setLevel(logging.INFO)
  logging.getLogger('progressive').setLevel(logging.INFO)
  logging.getLogger('progressive').addHandler(logging.StreamHandler(stream=sys.stdout))

  log.info('[+] output log to %s'% flog)

  opts.func(opts)


if __name__ == '__main__':
  main(sys.argv[1:])
