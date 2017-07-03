# -*- coding: utf-8 -*-

import logging
import struct

# from haystack.mappings import FileMapping
from haystack import target
from haystack.abc import interfaces
from haystack.mappings.base import MemoryHandler, AMemoryMapping

log = logging.getLogger("frida")


class FridaMapper(interfaces.IMemoryLoader):
    """
    """

    def __init__(self, process_name_or_pid, bits=None, os_name=None):
        import frida
        self.session = frida.attach(process_name_or_pid)
        self.name = process_name_or_pid
        self.cpu = bits
        self.os_name = os_name
        self._init_mappings()

    def _init_mappings(self):
        mappings = []
        #
        is_64 = False
        for _range in self.session.enumerate_ranges('r'):
            log.debug("Mapping Frida %s", _range)
            start = _range.base_address
            end = _range.base_address + _range.size
            perms = _range.protection
            mappings.append(FridaMemoryMapping(self.session, start, end, perms, None))
            if not is_64 and len(hex(start)) > 8:
                is_64 = True
        #
        self.mappings = mappings
        log.debug("nb maps: %d", len(self.mappings))
        # Use a folder name for its cache later on
        h_name = self.name + ".d"
        self._target = None
        # create the memory_handler for self

        # FIXME cpu, os_name from init param
        if 'linux' in sys.platform:
            os_name = target.TargetPlatform.LINUX
        else:  # sys.platform.startswith('win'):
            os_name = target.TargetPlatform.WIN7
        _target_platform = None
        if is_64:
            if os_name in [target.TargetPlatform.WINXP, target.TargetPlatform.WIN7]:
                _target_platform = target.TargetPlatform.make_target_win_64(os_name)
            elif os_name == target.TargetPlatform.LINUX:
                _target_platform = target.TargetPlatform.make_target_linux_64()
        else:
            if os_name in [target.TargetPlatform.WINXP, target.TargetPlatform.WIN7]:
                _target_platform = target.TargetPlatform.make_target_win_32(os_name)
            elif os_name == target.TargetPlatform.LINUX:
                _target_platform = target.TargetPlatform.make_target_linux_32()
        memory_handler = MemoryHandler(mappings, _target_platform, self.name)
        self._memory_handler = memory_handler
        return

    def make_memory_handler(self):
        return self._memory_handler


class FridaMemoryMapping(AMemoryMapping):

    """
    Frida memory mapping.

    Attributes:
     -

    Operations:
     - "readWord()": read a memory word, from local mmap-ed memory if mmap-ed
     - "readBytes()": read some bytes, from local mmap-ed memory if mmap-ed
     - "readStruct()": read a structure, from local mmap-ed memory if mmap-ed
     - "readArray()": read an array, from local mmap-ed memory if mmap-ed
         useful in list contexts
    """

    def __init__(self, frida_session, start, end, permissions, pathname):
        AMemoryMapping.__init__(self, start, end, permissions, 0, 0, 0, 0, pathname)
        self._session = frida_session

    def read_word(self, address):
        ws = self._utils.get_word_size()
        word = self._session.read_bytes(address, ws)
        if ws == 4:
            return struct.unpack('I', word)[0]
        elif ws == 8:
            return struct.unpack('Q', word)[0]

    def read_bytes(self, address, size):
        data = self._session.read_bytes(address, size)
        return data

    def read_struct(self, address, struct):
        size = self._ctypes.sizeof(struct)
        instance = struct.from_buffer_copy(self.read_bytes(address, size))
        instance._orig_address_ = address
        return instance

    def read_array(self, address, basetype, count):
        size = self._ctypes.sizeof(basetype * count)
        array = (basetype * count).from_buffer_copy(self.read_bytes(address, size))
        return array

    def __getstate__(self):
        d = dict(self.__dict__)
        d['session'] = None
        return d


class FridaLoader(interfaces.IMemoryLoader):
    desc = 'Load a Minidump memory dump'

    def __init__(self, opts):
        self.loader = FridaMapper(opts.target.netloc, bits=opts.bits, os_name=opts.osname)

    def make_memory_handler(self):
        return self.loader.make_memory_handler()


# haystack-search frida://test-ctypes6.64 ctypes6_gen64.struct_usual
# haystack-search frida://1242 ctypes6_gen64.struct_usual
if __name__ == '__main__':
    mapper = FridaMapper('test-ctypes6.64')
    memory_handler = mapper.make_memory_handler()
    m = memory_handler.get_mappings()[0]
    # py3
    print(m.read_bytes(m.start, 100).hex())
    # py2
    #print(m.read_bytes(m.start, 100).encode("hex"))
    my_model = memory_handler.get_model()
    import sys
    sys.path.append('test/src/')
    test6 = my_model.import_module("ctypes6_gen64")
    from haystack.search import api
    api.search_record(memory_handler, test6.struct_usual)