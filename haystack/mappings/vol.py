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

import volatility
from  volatility import conf
import volatility.constants as constants
import volatility.registry as registry
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.debug as debug

import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.scan as scan

class VolatilityProcessMapper:
    """
# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#
"""
    def __init__(self, imgname, pid):
        self.pid = pid
        self.imgname = imgname
        self.mappings = None
        self._init_volatility()
    
    def _init_volatility(self):
        # Get the version information on every output from the beginning
        # Exceptionally useful for debugging/telling people what's going on
        sys.stderr.write("Volatility Foundation Volatility Framework {0}\n".format(constants.VERSION))
        sys.stderr.flush()
        
        module = 'vadinfo'

        class MyOptionParser(conf.PyFlagOptionParser):
            def _get_args(myself,args):
                return ['-f', self.imgname, module,'-p', str(self.pid)]
        # singleton - replace with a controlled args list
        conf.ConfObject.optparser = MyOptionParser(add_help_option = False,
                                   version = False,)
        self.v_config = conf.ConfObject()
        conf.config = self.v_config

        # Load up modules in case they set config options
        registry.PluginImporter()

        ## Register all register_options for the various classes
        registry.register_global_options(self.v_config, addrspace.BaseAddressSpace)
        registry.register_global_options(self.v_config, commands.Command)

        ## Parse all the options now
        self.v_config.parse_options(False)
        # Reset the logging level now we know whether debug is set or not
        #debug.setup(self.v_config.DEBUG)

        ## Try to find the first thing that looks like a module name
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        
        if module not in cmds.keys():
            raise NotImplementedError('Volatility could not find module memmap')

        try:
            if module in cmds.keys():
                command = cmds[module](self.v_config)
                
                command.render_text = partial(my_render_text, self, command)
                self.v_config.parse_options()

                command.execute()
                #import code
                #code.interact(local=locals())
        
        except exceptions.VolatilityException, e:
            print e        

        

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


