# -*- coding: utf-8 -*-

"""
Volatility backed mappings.

- VolatilityProcessMapping: a wrapper around volatility addresspace
- VolatilityProcessMapper: the mappings builder.

http://computer.forensikblog.de/en/2007/05/walking-the-vad-tree.html
http://www.dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf
"""

import os
import logging
import struct
#import mmap
from functools import partial

# haystack
from haystack import utils
from haystack.mappings.base import MemoryMapping
from haystack.mappings.base import Mappings

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('volmapping')

class VolatilityProcessMapping(MemoryMapping):
    """Process memory mapping using volatility.
    """
    def __init__(self, address_space, start, end, permissions='r--', offset=0, major_device=0, minor_device=0, inode=0, pathname=''):
        MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._backend = address_space

    def readWord(self, addr ):
        ws = self.config.get_word_size()
        data = self._backend.zread(addr, ws)
        if ws == 4:
            return struct.unpack('I',data)[0]
        elif ws == 8:
            return struct.unpack('Q',data)[0]
            

    def readBytes(self, addr, size):
        return self._backend.zread(addr, size)
    
    def readStruct(self, addr, struct):
        size = self.config.ctypes.sizeof(struct)
        instance = struct.from_buffer_copy(self._backend.zread(addr, size))
        instance._orig_address_ = addr
        return instance

    def readArray(self, addr, basetype, count):
        size = self.config.ctypes.sizeof(basetype*count)
        array = (basetype*count).from_buffer_copy(self._backend.zread(addr, size))
        return array

import sys

class VolatilityProcessMapper:
    def __init__(self, imgname, pid):
        self.pid = pid
        self.imgname = imgname
        self.mappings = None
        self._init_volatility()
    
    def _init_volatility(self):
        import volatility
        import volatility.conf as conf
        import volatility.registry as registry
        registry.PluginImporter()
        config = conf.ConfObject()
        import volatility.commands as commands
        import volatility.addrspace as addrspace
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)
        config.parse_options()
        config.PROFILE="WinXPSP2x86"
        #config.LOCATION = "file:///media/memory/private/image.dmp"
        config.LOCATION = "file://%s"%self.imgname
        config.PID=str(self.pid)
        import volatility.plugins.vadinfo as vadinfo
        command = vadinfo.VADWalk(config)
        command.render_text = partial(my_render_text, self, command)
        command.execute()
        # works now.
        #for x in self.mappings:
        #    print x
        #import code
        #code.interact(local=locals())

    def getMappings(self):
        return self.mappings


PERMS_PROTECTION = dict(enumerate([
    '---', #'PAGE_NOACCESS',
    'r--',#'PAGE_READONLY',
    '--x',#'PAGE_EXECUTE',
    'r-x',#'PAGE_EXECUTE_READ',
    'rw-',#'PAGE_READWRITE',
    'rc-',#'PAGE_WRITECOPY',
    'rwx',#'PAGE_EXECUTE_READWRITE',
    'rcx',#'PAGE_EXECUTE_WRITECOPY',
    ]))



def my_render_text(mapper, cmd, outfd, data):
    maps = []
    for task in data:
        #print type(task)
        address_space = task.get_process_address_space()
        for vad in task.VadRoot.traverse():
            #print type(vad)
            if vad == None:
                continue
            offset = vad.obj_offset
            start = vad.Start
            end = vad.End
            tag = vad.Tag
            flags = str(vad.u.VadFlags)
            perms = PERMS_PROTECTION[vad.u.VadFlags.Protection.v() & 7]
            pathname = ''
            if vad.u.VadFlags.PrivateMemory == 1 or not vad.ControlArea:
                pathname = ''
            elif vad.FileObject:
                pathname = str(vad.FileObject.FileName or '')

            pmap = VolatilityProcessMapping(address_space, start, end, permissions=perms, pathname=pathname)
            #print pmap
            #import code
            #code.interact(local=locals())
            
            maps.append(pmap)

    mappings = Mappings(maps)
    #print mappings
    mappings.init_config()
    mapper.mappings = mappings


