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
  addrs = cmd_cmp(heap1, heap2, heap1.start)
  
  # now compare with structures addresses
  structures = []
  realloc=0
  log.info('[+] Looking at %d differences'%( len(addrs) ))
  st = []
  # joined iteration, found structure affected
  # use info from malloc : structures.start + .size 
  addr_iter = iter(addrs)
  structs_addr_iter = iter(context.malloc_addresses)
  structs_size_iter = iter(context.malloc_sizes) 
  try:
    addr = addr_iter.next()
    st_addr = structs_addr_iter.next()
    st_size = structs_size_iter.next()
    cnt=1
    while True:
        
      while (addr - st_addr) >= st_size : # find st containing offset
        st_addr = structs_addr_iter.next()
        st_size = structs_size_iter.next()
      # check for gaps
      if (addr - st_addr) < 0: # went to far - no struct overlapping
        while (addr - st_addr) < 0: # addr is in between two struct - dump all addr stuck out of malloc_chunks
          addr = addr_iter.next()
          pass
        continue
      
      #
      if 0 <= (addr - st_addr) < st_size: # check if offset is really in st ( should be always if your not dumb/there no holes )
        structures.append( context.structures[ st_addr ]) # tag the structure as different
        cnt+=1
      else: 
        ## (addr - st_addr) < 0 # impossible by previous while
        ## (addr - st_addr) >= st_size # then continur
        continue

      while (addr - st_addr) < st_size : # enumerate offsets in st range
        addr = addr_iter.next()
        cnt+=1
  except StopIteration,e:
    pass
  addrs_found = cnt
        
    
  log.info('[+] On %d diffs, found %d structs with different values. realloc: %d'%(addrs_found, len(structures), realloc))
  log.info('[+] Outputing to file (will be long-ish)')
  
  print_diff_files(opts, context, newmappings, structures)
  
def print_diff_files(opts, context, newmappings, structures):
  # print original struct in one file, diffed struct in the other
  d1out = config.Config.getCacheFilename(config.Config.DIFF_PY_HEADERS, '%s-%s'%(opts.dump1, opts.dump1) ) 
  d2out = config.Config.getCacheFilename(config.Config.DIFF_PY_HEADERS, '%s-%s'%(opts.dump1, opts.dump2) )
  f1 = file(d1out, 'w')
  f2 = file(d2out, 'w')
  for st in structures:
    st2 = structure.remapLoad(context, st.vaddr, newmappings)
    if st.bytes == st2.bytes: 
      print 'identic bit field !!!'
      return
    # get the fields
    ##### TODO FIXME , fix and leverage Field.getValue() to update from a changed mapping
    #### TODO, in toString(), pointer value should be in comment, to check for pointer change, when same pointed struct.
    st.decodeFields()
    #st.resolvePointers(context.structures_addresses, context.structures)
    #st._aggregateFields()
    st2.reset() # clean previous state
    st2.decodeFields()
    #st2.resolvePointers(context.structures_addresses, context.structures)
    #st2._aggregateFields()
    #write the files
    f1.write(st.toString())
    f1.write('\n')
    f2.write(st2.toString())
    f2.write('\n')
    sys.stdout.write('.')
    sys.stdout.flush()
  print 
  f1.close()
  f2.close()
  log.info('[+] diffed structures dumped in %s %s'%(d1out, d2out))

def cmd_cmp(heap1, heap2, baseOffset):
  # LINUX based system command cmp parsing
  import subprocess
  
  f1 = heap1._memdump.name
  f2 = heap2._memdump.name
  
  addrs = []
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
    addrs.append(int(cols.pop(0))+baseOffset -1 ) # starts with 1
  
  return addrs
  
  
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
