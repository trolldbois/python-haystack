#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging

log = logging.getLogger('good')


def populate():
    from haystack import model
    from haystack import constraints
    global Struct2
    Struct2.expectedValues = {
      'field1': constraints.RangeValue(1,16),
      }
 


