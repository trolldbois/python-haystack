# -*- coding: utf-8 -*-

"""
Volatility backed _memory_handler.

- VolatilityProcessMapping: a wrapper around volatility addresspace
- VolatilityProcessMapper: the _memory_handler builder.

http://computer.forensikblog.de/en/2007/05/walking-the-vad-tree.html
http://www.dfrws.org/2007/proceedings/p62-dolan-gavitt.pdf
"""

import logging
import struct
from functools import partial

from haystack.mappings.base import MemoryHandler, AMemoryMapping
from haystack.abc import interfaces
from haystack import target

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"
__credits__ = ["Victor Skinner"]

log = logging.getLogger('volmapping')


class VolatilityProcessMappingA(AMemoryMapping):

    """Process memory mapping using volatility.
    """

    def __init__(self, address_space, start, end, permissions='r--',
                 offset=0, major_device=0, minor_device=0, inode=0, pathname=''):
        AMemoryMapping.__init__(
            self,
            start,
            end,
            permissions,
            offset,
            major_device,
            minor_device,
            inode,
            pathname)
        self._backend = address_space

    def read_word(self, addr):
        ws = self._target_platform.get_word_size()
        data = self._backend.zread(addr, ws)
        if ws == 4:
            return struct.unpack('I', data)[0]
        elif ws == 8:
            return struct.unpack('Q', data)[0]

    def read_bytes(self, addr, size):
        return self._backend.zread(addr, size)

    def read_struct(self, addr, struct):
        size = self._target_platform.get_target_ctypes().sizeof(struct)
        instance = struct.from_buffer_copy(self._backend.zread(addr, size))
        instance._orig_address_ = addr
        return instance

    def read_array(self, addr, basetype, count):
        size = self._target_platform.get_target_ctypes().sizeof(basetype * count)
        array = (
            basetype *
            count).from_buffer_copy(
            self._backend.zread(
                addr,
                size))
        return array

    def reset(self):
        pass

import sys

class VolatilityProcessMapper(interfaces.IMemoryLoader):

    def __init__(self, imgname, profile, pid):
        self.pid = pid
        self.imgname = imgname
        self.profile = profile
        self._memory_handler = None
        self._unload_volatility()
        self._init_volatility()

    def _unload_volatility(self):
        '''we cannot have volatility already loaded.
        we need to remove it'''
        for mod in sys.modules.keys():
            if 'volatility' in mod:
                del sys.modules[mod]

    def _init_volatility(self):
        #import sys
        # for mod in sys.modules.keys():
        #    if 'parse' in mod:
        #        del sys.modules[mod]
        #        print "deleted",mod
        #import sys
        # if len(sys.argv) > 3:
        #    #sys.args=[sys.args[3]]
        #    sys.argv=[sys.argv[0],'-f',sys.argv[3]]
        # print 'after modif',sys.argv
        import volatility.conf as conf
        import volatility.registry as registry
        registry.PluginImporter()
        config = conf.ConfObject()
        import volatility.commands as commands
        import volatility.addrspace as addrspace
        registry.register_global_options(config, commands.Command)
        registry.register_global_options(config, addrspace.BaseAddressSpace)
        config.parse_options()
        config.PROFILE = self.profile
        #_target_platform.LOCATION = "file:///media/memory/private/image.dmp"
        config.LOCATION = "file://%s" % self.imgname
        config.PID = str(self.pid)

        self.config = config

        import volatility.plugins.vadinfo as vadinfo

        #import code
        #print _target_platform.__dict__
        # code.interact(local=locals())

        command = vadinfo.VADWalk(config)
        command.render_text = partial(my_render_text, self, command)
        command.execute()
        # works now.
        # for x in self._memory_handler:
        #    print x
        #import code
        # code.interact(local=locals())

    def make_memory_handler(self):
        return self._memory_handler


PERMS_PROTECTION = dict(enumerate([
    '---',  # 'PAGE_NOACCESS',
    'r--',  # 'PAGE_READONLY',
    '--x',  # 'PAGE_EXECUTE',
    'r-x',  # 'PAGE_EXECUTE_READ',
    'rw-',  # 'PAGE_READWRITE',
    'rc-',  # 'PAGE_WRITECOPY',
    'rwx',  # 'PAGE_EXECUTE_READWRITE',
    'rcx',  # 'PAGE_EXECUTE_WRITECOPY',
]))


def my_render_text(mapper, cmd, outfd, data):
    maps = []
    for task in data:
        # print type(task)
        address_space = task.get_process_address_space()
        for vad in task.VadRoot.traverse():
            # print type(vad)
            if vad is None:
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

            pmap = VolatilityProcessMappingA(
                address_space,
                start,
                end,
                permissions=perms,
                pathname=pathname)
            # print pmap
            #import code
            # code.interact(local=locals())

            maps.append(pmap)

    # get the platform
    if mapper.config.PROFILE == "WinXPSP2x86":
        mapper._target = target.TargetPlatform.make_target_win_32('winxp')
    memory_handler = MemoryHandler(maps, mapper._target, mapper.imgname)
    # print _memory_handler
    #mappings.init_config()
    mapper._memory_handler = memory_handler
