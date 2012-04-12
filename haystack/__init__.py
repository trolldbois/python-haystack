#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

# try to fetch pydoc
from pkg_resources import Requirement, resource_filename
__doc__ = open(resource_filename(Requirement.parse("haystack"),"README")).read()

# DEFINE the API.
import abouchet 

findStruct = abouchet.findStruct
findStructInFile = abouchet.findStructInFile
refreshStruct = abouchet.refreshStruct
search = abouchet.search
refresh = abouchet.refresh

all =[
  findStruct,
  findStructInFile,
  refreshStruct,
  search,
  refresh
]


