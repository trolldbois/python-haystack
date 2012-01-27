#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Some helpers for argparse."""

import os

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

def readable(f):
  """Validates if the pathname is readable (dir or file)."""
  f = os.path.normpath(f)
  if not os.access(f, os.F_OK|os.R_OK):
    raise ValueError("%s is not readable."%(f))
  return f

def writeable(f):
  """Validates if the pathname is writable (dir or file)."""
  f = os.path.normpath(f)
  if os.access(f, os.F_OK):
    if not os.access(f, os.W_OK):
      raise ValueError("%s is not writable."%(f))
  return f

def int16(s):
  """Validates an hexadecimal (0x...) value"""
  i=int(s,16)
  return i
