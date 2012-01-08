#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Default configuration for filenames, output directories and such."""

import logging
import os

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger('config')

OUTPUTDIR=os.path.expanduser('~/outputs/malloc/') # .haystack-tmp ?

class ConfigClass():
  """Project-wide config class. """
  def __init__(self, outputDir=OUTPUTDIR):
    self.cacheDir = os.path.normpath(outputDir)
    self.imgCacheDir = os.path.sep.join([self.cacheDir,'img'])
    self.WORDSIZE = 4
    self.commentMaxSize = 64
    #
    self.CACHE_STRUCT_DIR = '.structs'
    # cache file names
    self.CACHE_GENERATED_PY_HEADERS_VALUES = '.headers_values.py'
    self.CACHE_GENERATED_PY_HEADERS = '.headers.py'
    self.CACHE_HS_POINTERS_VALUES = '.heap+stack.pointers.values'
    self.CACHE_HEAP_ADDRS = '.heap.pointers.addrs'
    self.CACHE_STACK_ADDRS = '.stack.pointers.offsets'
    self.CACHE_STACK_VALUES = '.stack.pointers.values'
    self.CACHE_STRUCTURES = '.structures'
    self.CACHE_MALLOC_CHUNKS_ADDRS = '.mchunks.addrs'
    self.CACHE_MALLOC_CHUNKS_SIZES = '.mchunks.sizes'
    self.CACHE_CONTEXT = '.ctx'
    self.CACHE_GRAPH = '.gexf'
    self.DIFF_PY_HEADERS='.diff_headers'
  
  def getCacheFilename(self, typ, dumpfilename):
    '''Returns a filename for caching a type of data based on the dump filename.
  
    typ: one of Config.CACHE_XX types.
    dumpfilename: the dump file name.
    '''
    root = os.path.basename(dumpfilename)
    return os.path.sep.join([self.cacheDir, root+typ])

  def getStructsCacheDir(self, dumpfilename):
    '''Returns a dirname for caching the structures based on the dump filename.
  
    dumpfilename: the dump file name.
    '''
    root = os.path.basename(dumpfilename)
    return self.getCacheFilename(self.CACHE_STRUCT_DIR, root)


Config = ConfigClass()

