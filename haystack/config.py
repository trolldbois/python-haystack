#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import os

from haystack.utils import Dummy

log = logging.getLogger('config')

OUTPUTDIR=os.path.expanduser('~/Compil/python-haystack/outputs/')

class ConfigClass():
  def __init__(self, outputDir=OUTPUTDIR):
    self.cacheDir = os.path.normpath(outputDir)
    self.structsCacheDir = os.path.sep.join([self.cacheDir,'structs'])
    self.imgCacheDir = os.path.sep.join([self.cacheDir,'img'])
    self.WORDSIZE = 4
    self.commentMaxSize = 64
    # cache file names
    self.CACHE_GENERATED_PY_HEADERS_VALUES = '.headers_values.py'
    self.CACHE_GENERATED_PY_HEADERS = '.headers.py'
    self.CACHE_HS_POINTERS_VALUES = '.heap+stack.pointers.values'
    self.CACHE_HEAP_ADDRS = '.heap.pointers.addrs'
    self.CACHE_STACK_ADDRS = '.stack.pointers.offsets'
    self.CACHE_STACK_VALUES = '.stack.pointers.values'
    self.CACHE_STRUCTURES = '.structures'
    self.CACHE_CONTEXT = '.ctx'
    self.CACHE_GRAPH = '.gexf'
    self.DIFF_PY_HEADERS='.diff_headers'
  
  ''' 
  @param typ: one of Config.CACHE_XX types'''
  def getCacheFilename(self, typ, dumpfilename):
    root = os.path.basename(dumpfilename)
    return os.path.sep.join([self.cacheDir, root+typ])


Config = ConfigClass()

