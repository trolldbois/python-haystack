#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import os

from utils import Dummy

log = logging.getLogger('config')

OUTPUTDIR=os.path.expanduser('~/Compil/python-haystack/outputs/')

Config = Dummy()
Config.cacheDir = os.path.normpath(OUTPUTDIR)
Config.structsCacheDir = os.path.sep.join([Config.cacheDir,'structs'])
Config.GENERATED_PY_HEADERS_VALUES = os.path.sep.join([Config.cacheDir,'headers_values.py'])
Config.GENERATED_PY_HEADERS = os.path.sep.join([Config.cacheDir,'headers.py'])
Config.WORDSIZE = 4

