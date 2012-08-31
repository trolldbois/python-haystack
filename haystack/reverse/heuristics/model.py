#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import os
import collections
import struct
import itertools

from haystack.config import Config
from haystack.utils import unpackWord
from haystack.reverse import re_string, fieldtypes

import ctypes

log = logging.getLogger('heuristics.model')

class FieldAnalyser(object):

  def make_fields(self, structure, offset, size):
    '''
    @param structure: the structure object, with a bytes()
    @param offset: the offset of the field to analyze
    @param size: the size of said field
    
    @return False, or [Field(), ]
    '''
    raise NotImplementedError('This should be implemented.')

class StructuredAnalyser(object):
  ''' StructureAnalyzer should apply heuristics on the structure, all fields included, 
  and try to determine specific field types that are identifiable with a 
  full structure-view.
  '''
  def analyze_fields(self, structure):
    '''
    @param structure: the AnonymousStructure to analyze and modify
    
    @returns
    '''
    raise NotImplementedError('This should be implemented.')


