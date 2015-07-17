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
    'find_struct_process',
    'find_struct_memfile',
    'refresh_struct_process',
    'search_struct_process',
    'search_struct_memfile',
    'search_struct_dumpname',
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

# DEFINE the API.
import api

find_struct_process = api.find_struct_process
find_struct_memfile = api.find_struct_memfile
refresh_struct_process = api.refresh_struct_process

search_struct_process = api.search_struct_process
search_struct_memfile = api.search_struct_memfile
search_struct_dumpname = api.search_struct_dumpname
refresh = api.refresh
show_dumpname = api.show_dumpname

def _set_rlimits():
    """set rlimits to maximum allowed"""
    import resource
    maxnofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (maxnofile[1],
         maxnofile[1]))
    return