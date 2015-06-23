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

from pkg_resources import get_distribution, DistributionNotFound
import os.path

try:
    _dist = get_distribution('haystack')
    # Normalize case for Windows systems
    dist_loc = os.path.normcase(_dist.location)
    here = os.path.normcase(__file__)
    if not here.startswith(os.path.join(dist_loc, 'haystack')):
        # not installed, but there is another version that *is*
        raise DistributionNotFound
except DistributionNotFound:
    __version__ = 'Please install this project with setup.py'
else:
    __version__ = _dist.version

# in any haystack import, we need to ensure the model is loaded.
import model

# DEFINE the API.
#import abouchet

#findStruct = abouchet.findStruct
#findStructInFile = abouchet.findStructInFile
#refreshStruct = abouchet.refreshStruct

#search_process = abouchet.search_process
#search_memfile = abouchet.search_memfile
#search_dumpname = abouchet.search_dumpname
#refresh = abouchet.refresh
#show_dumpname = abouchet.show_dumpname
