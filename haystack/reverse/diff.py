#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Utils to diff two heap memory mappings."""

import argparse
import logging
import os
import sys
import difflib
import mmap
import timeit
from collections import defaultdict

from haystack import config
from haystack import argparse_utils
from haystack.reverse import utils
from haystack.reverse import reversers
from haystack.reverse.reversers import *

import code

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"


log = logging.getLogger('diff')


def make(opts):
  log.info('[+] Loading context of %s'%(opts.dump1))
  context = reversers.getContext(opts.dump1) #'../../outputs/skype.1.a') # TODO 
  # refresh
  if len(context.structures) != len(context.structures_addresses):
    log.info('[+] Refreshing from %d structures cached'%( len(context.structures) ))
    mallocRev = MallocReverser()
    context = mallocRev.reverse(context)
    mallocRev.check_inuse(context)
    log.info('[+] Final %d structures from malloc blocs'%( len(context.structures) ))

  
  heap1 = context.mappings.getHeap()
  log.info('[+] Loading mappings of %s'%(opts.dump2))
  newmappings = dump_loader.load( opts.dump2)  
  heap2 = newmappings.getHeap()
  log.info('[+] finding diff values with %s'%(opts.dump2))
  #offsets = findDiffsOffsets_mappings(heap1, heap2, heap1.start)
  #offsets = diff_iterator(heap1, heap2, heap1.start)
  offsets = cmd_cmp(heap1, heap2, heap1.start)
  
  # now compare with structures addresses
  structures = []
  log.info('[+] Looking at %d offsets'%( len(offsets) ))
  st = []
  saved=0
  for offsets_found, offset in enumerate(offsets):
    if offset in st: # last structure could hold this offset too
      saved+=1
      continue
    vaddr, pos = utils.closestFloorValueNumpy(offset, context.structures_addresses)
    st = context.structures[vaddr]
    structures.append(st)
  log.info('[+] On %d diffs, found %d structs with different values. saved: %d'%(offsets_found, len(structures), saved))
  log.info('[+] Outputing to file (will be long-ish)')

  # print original struct in one file, diffed struct in the other
  d1out = config.Config.getCacheFilename(config.Config.DIFF_PY_HEADERS, opts.dump1) 
  d2out = config.Config.getCacheFilename(config.Config.DIFF_PY_HEADERS, opts.dump2) 
  f1 = file(d1out, 'w')
  f2 = file(d2out, 'w')
  for st in structures:
    st2 = structure.remapLoad(context, st.vaddr, newmappings)
    # get the fields
    ##### TODO FIXME , fix and leverage Field.getValue() to update from a changed mapping
    #### TODO, in toString(), pointer value should be in comment, to check for pointer change, when same pointed struct.
    st.decodeFields()
    #st.resolvePointers(context.structures_addresses, context.structures)
    #st._aggregateFields()
    st2.decodeFields()
    #st2.resolvePointers(context.structures_addresses, context.structures)
    #st2._aggregateFields()
    #write the files
    f1.write(st.toString())
    f1.write('\n')
    f2.write(st2.toString())
    f2.write('\n')
  f1.close()
  f2.close()
  log.info('[+] diffed structures dumped in %s %s'%(d1out, d2out))

def findDiffsOffsets_files(file1, file2, baseOffset):
  '''Makes a dichotomic search of unequals values in bytebuffers.
  returns offsets of unequals word value
  '''
  size1 = os.fstat(file1.fileno()).st_size
  size2 = os.fstat(file2.fileno()).st_size
  if size1 != size2:
    log.debug('different sizes')
  d1 = mmap.mmap(file1.fileno(), size1, access=mmap.ACCESS_READ)
  d2 = mmap.mmap(file2.fileno(), size2, access=mmap.ACCESS_READ)
  #
  offsets = []
  buflen=2**16
  offset=0
  while offset < size1 and offset < size2:
    data1 = d1.read(buflen) 
    data2 = d2.read(buflen) 
    if data1 != data2:
      diffs = cmp_recursive(buflen, data1, data2, baseOffset)
      offsets.extend(diffs)
      #log.debug('%d diff at offsets %d'%(len(diffs), offset))
    offset += buflen
    baseOffset += buflen
  log.debug('simple finished with %d diffs'%(len(offsets)))
  return sorted(offsets)

def findDiffsOffsets_mappings(heap1, heap2, baseOffset):
  size1 = len(heap1)
  size2 = len(heap2)
  if size1 != size2:
    log.debug('different sizes')
  #
  offsets = []
  buflen=2**16
  offset=0
  while offset < size1 and offset < size2:
    data1 = heap1.readBytes(baseOffset, buflen) 
    data2 = heap2.readBytes(baseOffset, buflen) 
    if data1 != data2:
      diffs = cmp_recursive(buflen, data1, data2, baseOffset)
      offsets.extend(diffs)
      #log.debug('%d diff at offsets %d'%(len(diffs), offset))
    offset += buflen
    baseOffset += buflen
  log.debug('simple finished with %d diffs'%(len(offsets)))
  return sorted(offsets)

'''
Make a recursive dichotomic comparaison
'''
def cmp_recursive(buflen, data1, data2, offset):
  if buflen < config.Config.WORDSIZE+1: # find word difference
    return [offset] # 0+offset or mid+offset
  offsets = []
  mid = min(min(buflen/2, len(data1) ), len(data2) )
  #print mid+offset, len(data1)
  d1g = data1[:mid]
  d2g = data2[:mid]
  if d1g != d2g:
    offsets.extend( cmp_recursive(mid, d1g, d2g, offset) )
  d1d = data1[mid:]
  d2d = data2[mid:]
  if d1d != d2d:
    offsets.extend( cmp_recursive(mid, d1d, d2d, offset+mid) )
  return offsets


def diff_iterator(heap1, heap2, baseOffset):
  
  def my_iter(heap1, heap2, baseOffset):
    size1 = len(heap1)
    size2 = len(heap2)
    if size1 != size2:
      log.debug('different sizes')
    
    h1 = heap1.getByteBuffer()
    h2 = heap2.getByteBuffer()
    offsets = []
    offset=0
    for offset in xrange( min(size1,size2)):
      if h1[offset] != h2[offset]:
        yield(baseOffset + offset)
    return  
  return iter(my_iter(heap1, heap2, baseOffset))
  

def cmd_cmp(heap1, heap2, baseOffset):
  # LINUX based system command cmp parsing
  import subprocess
  
  f1 = heap1._memdump.name
  f2 = heap2._memdump.name
  
  offsets = []
  try:
    res = subprocess.check_output(['cmp',f1,f2,'-l'])
  except subprocess.CalledProcessError,e:
    res = e.output
  for line in res.split('\n'):
    cols = line.split(' ')
    try:
      while cols[0] == '':
        cols.pop(0)
    except:
      continue
    offsets.append(int(cols.pop(0)))
  
  return offsets
  
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-reversers-diff', description='Diff struct of the same instance.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('dump1', type=argparse_utils.readable, action='store', help='Dump file 1.')
  rootparser.add_argument('dump2', type=argparse_utils.readable, action='store', help='Dump file 2.')
  rootparser.set_defaults(func=make)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)

  level=logging.INFO
  if opts.debug :
    level=logging.DEBUG
  
  flog = os.path.sep.join([config.Config.cacheDir,'log'])
  logging.basicConfig(level=level, filename=flog, filemode='w')
  
  logging.getLogger('diff').addHandler(logging.StreamHandler(stream=sys.stdout))

  log.info('[+] output log to %s'% flog)

  opts.func(opts)


if __name__ == '__main__':
  main(sys.argv[1:])
