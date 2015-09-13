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
]

# verify the version
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

# search API
from haystack.search import api
search_record = api.search_record
output_to_string = api.output_to_string
output_to_python = api.output_to_python

try:
    import resource
    # augment our file limit capacity to max
    maxnofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    # print 'maxnofile', maxnofile
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (maxnofile[1],
         maxnofile[1]))
    # maxnofile_after = resource.getrlimit(resource.RLIMIT_NOFILE)
    # print 'maxnofile_after', maxnofile_after
    # travis-ci says
    # maxnofile (64000, 64000)
    # maxnofile_after (64000, 64000)
except ImportError, e:
    pass


# bad bad idea...
MMAP_HACK_ACTIVE = True
# do not load huge mmap
MAX_MAPPING_SIZE_FOR_MMAP = 1024 * 1024 * 20
