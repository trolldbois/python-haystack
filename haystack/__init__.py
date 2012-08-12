# -*- coding: utf-8 -*-

"""
:mod:`haystack` -- a package to search known C or ctypes structures in memory.
==============================================================================
.. module:: haystack
    :platform: Unix, Windows
    :synopsys: Search, reverse C/ctypes structures from memory.
.. moduleauthor:: Loic Jaquemet <loic.jaquemet+python [at] gmail.com>

Available subpackages
---------------------
gui
    An attempt to make a Qt4 GUI.
reverse
    Framework to reverse engineer memory structures

"""

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

__all__ = [
  'findStruct',
  'findStructInFile',
  'refreshStruct',
  'search_process',
  'search_memfile',
  'search_dumpname',
  'refresh'
]

# DEFINE the API.
import abouchet 

findStruct = abouchet.findStruct
findStructInFile = abouchet.findStructInFile
refreshStruct = abouchet.refreshStruct

search_process = abouchet.search_process
search_memfile = abouchet.search_memfile
search_dumpname = abouchet.search_dumpname
refresh = abouchet.refresh
show_dumpname = abouchet.show_dumpname



