#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import logging
import os
import sys
import difflib
import mmap
import timeit
from collections import defaultdict

from haystack import config
from haystack.reverse import utils
from haystack.reverse import reversers
from reversers import *

log = logging.getLogger('diff')


def make(opts):
  log.info('[+] Loading context of %s'%(opts.dump1.name))
  context = reversers.getContext('../../outputs/skype.1.a') # TODO 
  heap = context.mappings.getHeap()
  log.info('[+] finding diff values with %s'%(opts.dump2.name))
  offsets = findDiffsOffsets(opts.dump1, opts.dump2, heap.start)
  # now compare with structures addresses
  structures = set()
  for offset in offsets:
    vaddr, pos = utils.closestFloorValueNumpy(offset, context.structures_addresses)
    st = context.structures[vaddr]
    structures.add(st)
  log.info('[+] On %d diffs, found %d structs'%( len(offsets), len(structures) ))
  
'''
Make a dichotomic search of unequals values in bytebuffers.
returns offsets of unequals word value
'''
def findDiffsOffsets(file1, file2, baseOffset):
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
  
  
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-reversers-diff', description='Diff struct of the same instance.')
  rootparser.add_argument('--debug', action='store_true', help='Debug mode on.')
  rootparser.add_argument('dump1', type=argparse.FileType('rb'), action='store', help='Dump file 1.')
  rootparser.add_argument('dump2', type=argparse.FileType('rb'), action='store', help='Dump file 2.')
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
