#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

from haystack import model
from haystack import constraints

import logging
import sys

log = logging.getLogger('bad')

from bad_gen import *

Struct1.expectedValues = {
    'field1': constraints.RangeValue(1, 16),
}
