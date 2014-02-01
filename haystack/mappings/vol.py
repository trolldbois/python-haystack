# -*- coding: utf-8 -*-

"""
Volatility backed mappings.

- VolatilityProcessMapping: a wrapper around volatility addresspace
- VolatilityProcessMapper: the mappings builder.

"""

import os
import logging
import struct
import mmap

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
    """Process memory mapping using volatitlity.
    """
    def __init__(self, task_space, start, end, permissions='r--', offset=0, major_device=0, minor_device=0, inode=0, pathname=''):
        MemoryMapping.__init__(self, start, end, permissions, offset, major_device, minor_device, inode, pathname)
        self._backend = task_space

    def readWord(self, vaddr ):
        ws = self.config.get_word_size()
        return self._backend.read(vaddr, ws)
    
    def readStruct(self, vaddr, struct):
        laddr = self.vtop( vaddr )
        struct = struct.from_address(int(laddr))
        #struct = struct.from_buffer_copy(struct.from_address(int(laddr)))
        struct._orig_address_ = vaddr
        return struct

    def readArray(self, vaddr, basetype, count):
        laddr = self.vtop( vaddr )
        array = (basetype *count).from_address(int(laddr))
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

        class MyOptionParser(conf.PyFlagOptionParser):
            def _get_args(myself,args):
                return ['-f', self.imgname, 'memmap','-p', str(self.pid)]
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
        module = 'memmap'
        # Reset the logging level now we know whether debug is set or not
        #debug.setup(self.v_config.DEBUG)

        ## Try to find the first thing that looks like a module name
        cmds = registry.get_plugin_classes(commands.Command, lower = True)
        
        if module not in cmds.keys():
            raise NotImplementedError('Volatility could not find module memmap')

        try:
            if module in cmds.keys():
                command = cmds[module](self.v_config)
                
                command.render_text = my_render_text
                self.v_config.parse_options()

                command.execute()
                import code
                code.interact(local=locals())
        
        except exceptions.VolatilityException, e:
            print e        

        

    def getMappings(self):
        return self.mappings



def my_render_text(outfd, data):
    first = True
    for pid, task, pagedata in data: # only one.

        task_space = task.get_process_address_space()
        
        # TODO
        # task_space is Mapping
        # task_space.read
        
        #task.ImageFileName
        maps = []
       
        expected = -1
        done = False
        ordered_pages = [(p[0],p[1]) for p in pagedata]
        ordered_pages.sort()
        for p in ordered_pages: #[:10]:
            # task_space.vtop( I dont want the physical address.
            start = p[0]
            size = p[1]
            end2 = start - size
            end = start + size
            #print '%x %x %x %x'%(start, end, end2, size)
            
            
            if expected == -1:
                current_start = start
                expected = start
    
            if start == expected:
                expected = end
                done = False
                #print hex(start), hex(end)
                continue
            else:
                # merge
                #print 'merged', hex(current_start), hex(end), (end-current_start)/4096, 'pages'
                maps.append(VolatilityProcessMapping(task_space, current_start, end))
                print maps[-1]
                current_start = start
                expected = end
                done = True
        # tail
        if not done:
            maps.append(VolatilityProcessMapping(task_space, current_start, end))
        
        mappings = Mappings(maps)
        print mappings


