#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module holds some basic utils function.
'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os
import array
import logging

log = logging.getLogger('cache_utils')

class Dummy(object):
  pass

def int_array_cache(filename):
  if os.access(filename,os.F_OK):
    # load
    f = file(filename,'r')
    nb = os.path.getsize(f.name)/4 # simple TODO 
    my_array = array.array('L')
    my_array.fromfile(f,nb)
    return my_array
  return None

def int_array_save(filename, lst):
  my_array = array.array('L')
  my_array.extend(lst)
  my_array.tofile(file(filename,'w'))
  return my_array

