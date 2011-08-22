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

import memory_dumper
import signature

log = logging.getLogger('pointerfinder')


def _openDumpfile(dumpfile):
  # load memorymapping
  mappings = memory_dumper.load(dumpfile)
  # TODO : make a mapping chooser 
  stack, heap = None, None
  if len(mappings) > 1:
    for m in mappings:
      if m.pathname == '[heap]':
        heap = m 
      if m.pathname == '[stack]':
        stack = m 
  if heap is None or stack is None:
    log.info('Heap or stack has not been found( head:%s stack:%s'%(heap, stack))
    return None
  return heap,stack,mappings

def mergeDump(dumpFile):
  log.info('Loading the mappings in the memory dump file.')
  mappings = _openDumpfile(dumpFile)
  if mappings is None:
    return
  heap,stack,mappings = mappings
  #log.info('Make the signature.')
  #sigMaker = SignatureMaker(mapping)
  #sig = sigMaker.search()

  # get pointers in stack
  stackSearcher = signature.TargetMappingPointerSearcher(heap, stack)
  heapSearcher = signature.PointerSearcher(heap)
  pointersFromHeap  = heapSearcher.search()
  pointersFromStack = stackSearcher.search()
  pointersFromHeap = sorted(pointersFromHeap)
  pointersFromStack = sorted(pointersFromStack)
  log.info('%d heap pointers in stack'%( len(pointersFromStack) ))
  log.info('%d heap pointers in heap'%( len(pointersFromHeap) ))
  # common ones
  intersex = set(pointersFromHeap) & set(pointersFromStack)
  log.info('%d heap pointers in both'%( len(intersex) ))
  # all
  allpointers = []
  #allpointers.extend(pointersFromHeap)
  allpointers.extend(pointersFromStack)
  allpointers = sorted(set(allpointers))
  # give intervals between pointers
  intervals=[]
  for p in xrange(1,len(allpointers)-1):
    val = allpointers[p] - allpointers[p-1]
    intervals.append(val)
  return

def merge(opt):
  mergeDump(opt.dumpfile)
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-pointer-merge', description='Collect heap pointers in heap, heap pointers in stack, relative position in stack, and try to guess structures with all that.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memory dump by haystack.')
  #rootparser.add_argument('sigfile', type=argparse.FileType('wb'), action='store', help='The output signature filename.')
  rootparser.set_defaults(func=merge)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('ctypes_openssh').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('gui').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
