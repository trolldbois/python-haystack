# -*- coding: utf-8 -*-

import logging

from haystack import target
from haystack.abc import interfaces
from haystack.mappings import file
from haystack.mappings.base import MemoryHandler

log = logging.getLogger("coredump")


class CoreMapper(interfaces.IMemoryLoader):
    """
    use pyelftools to parse core dump file format
    """

    def __init__(self, filename):
        from elftools.elf.elffile import ELFFile
        self.elffile = ELFFile(open(filename, 'rb'))
        self.name = filename
        self._init_mappings()

    def _init_mappings(self):
        mappings = []
        for segment in self.elffile.iter_segments():
            start = segment['p_vaddr']
            pstart = segment['p_paddr']
            size = segment['p_filesz']
            memsize = segment['p_memsz']
            end = start + size
            perms = segment['p_flags']
            offset = segment['p_offset']
            align = segment['p_align']

            # can't use segment.stream decently.
            mappings.append(file.FilenameBackedMemoryMapping(self.name, start, end, offset=offset, pathname=''))
            print(mappings[-1])

        log.debug("nb maps: %d", len(mappings))
        # create the memory_handler for self
        self._target = None
        os_name = target.TargetPlatform.LINUX
        _target_platform = None
        bits = self.elffile.elfclass
        if bits == 32:
            _target_platform = target.TargetPlatform.make_target_linux_32()
        else:
            _target_platform = target.TargetPlatform.make_target_linux_64()
        memory_handler = MemoryHandler(mappings, _target_platform, self.name)
        self._memory_handler = memory_handler
        return

    def make_memory_handler(self):
        return self._memory_handler


class CoreLoader(interfaces.IMemoryLoader):
    desc = 'Load a Core dump memory dump'

    def __init__(self, opts):
        self.loader = CoreMapper(opts.target.netloc)

    def make_memory_handler(self):
        return self.loader.make_memory_handler()


if __name__ == '__main__':
    mapper = CoreMapper('test/dumps/core/cat.core')
    memory_handler = mapper.make_memory_handler()
    m = memory_handler.get_mappings()[0]
    # py3
    #print(m.read_bytes(m.start, 100).hex())
    # py2
    print(m.read_bytes(m.start, 100).encode("hex"))
