#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This module offers several classes in charge of loading the memory
mapping dumps into a MemoryMappings list of MemoryMapping, given a
previously saved format ( file, archive, ... ).
Basically MemoryMappings are in archive of all the mappings dumped to
file + a special 'mappings' index file that give all metadata about
thoses mappings.

Classes:
 - MemoryDumpLoader:    abstract loader for a memory dump loader
 - ProcessMemoryDumpLoader: handles memory load from several recognized
        format.
 - KCoreDumpLoader: Mapping loader for kernel memory mappings dumps.

Functions:
 - load: load MemoryMappings from the source dumpname.

"""

import os
import platform
import logging
import zipfile  # relatively useless

from haystack import config
from haystack import types
from haystack.abc import interfaces
from haystack.mappings.base import MemoryHandler, AMemoryMapping
from haystack.mappings.file import FileBackedMemoryMapping
from haystack.mappings.file import FilenameBackedMemoryMapping
from haystack.mappings.file import LocalMemoryMapping
from haystack.mappings.file import MemoryDumpMemoryMapping
from haystack.structures.heapwalker import log

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

log = logging.getLogger('dump_loader')


class LazyLoadingException(Exception):

    def __init__(self, filename):
        Exception.__init__(self)
        self._filename = filename
        return


class MemoryDumpLoader(object):

    ''' Abstract interface to a memory dump loader.

    isValid and loadMapping should be implemented.
    '''

    def __init__(self, dumpname, cpu=None, os_name=None):
        self._cpu_bits = cpu
        self._os_name = os_name
        self.dumpname = os.path.normpath(dumpname)
        self.mappings = None
        if not self._is_valid():
            raise ValueError(
                'memory dump not valid for %s ' %
                (self.__class__))

    def getMappings(self):
        if self.mappings is None:
            self._load_mappings()
        return self.mappings

    def _is_valid(self):
        raise NotImplementedError()

    def _load_mappings(self):
        raise NotImplementedError()


class ProcessMemoryDumpLoader(MemoryDumpLoader):

    """ Handles memory load from several recognized format."""
    indexFilename = 'mappings'
    filePrefix = './'

    def _is_valid(self):
        """Validates if we handle the format."""
        if os.path.isdir(self.dumpname):
            if self._test_dir():
                self._open_archive = lambda archive: archive
                self._list_names = os.listdir
                self._open_file = lambda archive, name: file(
                    os.path.sep.join([archive, name]), 'rb')
                return True
        else:
            raise IOError('%s is not a directory' % (self.dumpname))
        return False

    def _test_dir(self):
        try:
            self.archive = self.dumpname
            members = os.listdir(self.archive)
            if self.indexFilename not in members:
                log.error('no mappings index file in the directory.')
                return False
            self.filePrefix = ''
            self.mmaps = [m for m in members if '-0x' in m]
            if len(self.mmaps) > 0:
                return True
        except OSError as e:
            log.info('Not a valid directory')
        return False

    def _protected_open_file(self, mmap_fname, mmap_pathname):
        return self._open_file(self.archive, self.filePrefix + mmap_fname)

    def _load_mappings(self):
        """Loads the mappings content from the dump to a MemoryMappings.

        If an underlying file containing a memory dump does not exists, still
        create a MemoryMap for metadata purposes.
        If the memory map is > config.MAX_MAPPING_SIZE_FOR_MMAP, use a slow FileBackedMemoryMapping.
        Else, load the mapping in memory.
        """
        self._load_metadata()
        self._load_memory_mappings()  # set self.mappings
        return

    def _load_metadata(self):
        """ Load    amemory dump meta data """
        mappingsFile = self._open_file(self.archive, self.indexFilename)
        self.metalines = []
        for l in mappingsFile.readlines():
            fields = l.strip().split(' ')
            if '' in fields:
                fields.remove('')
            self.metalines.append(
                (fields[0],
                 fields[1],
                    fields[2],
                    fields[3],
                    fields[4],
                    fields[5],
                    ' '.join(
                    fields[
                        6:])))
        return

    def _load_memory_mappings(self):
        """ make the python objects"""
        self.mappings = MemoryHandler(None, self.dumpname)
        for _start, _end, permissions, offset, devices, inode, mmap_pathname in self.metalines:
            start, end = int(_start, 16), int(_end, 16)
            offset = int(offset, 16)
            inode = int(inode)
            # rebuild filename
            mmap_fname = "%s-%s" % (_start, _end)
            # get devices nums
            major_device, minor_device = devices.split(':')
            major_device = int(major_device, 16)
            minor_device = int(minor_device, 16)
            log.debug('Loading %s - %s' % (mmap_fname, mmap_pathname))
            # open the file in the archive
            try:
                mmap_content_file = self._protected_open_file(
                    mmap_fname,
                    mmap_pathname)
            except (IOError, KeyError) as e:
                log.debug('Ignore absent file : %s' % (e))
                mmap = AMemoryMapping(start, end, permissions, offset,
                                     major_device, minor_device, inode, pathname=mmap_pathname)
                self.mappings.append(mmap)
                continue
            # except ValueError,e: # explicit non-loading
            #    log.debug('Ignore useless file : %s'%(e))
            #    mmap = MemoryMapping(start, end, permissions, offset,
            #                                                    major_device, minor_device, inode,pathname=mmap_pathname)
            #    self.mappings.append(mmap)
            #    continue
            except LazyLoadingException as e:
                mmap = FilenameBackedMemoryMapping(e._filename, start, end, permissions, offset,
                                                   major_device, minor_device, inode, pathname=mmap_pathname)
                self.mappings.append(mmap)
                continue

            if isinstance(self.archive, zipfile.ZipFile):  # ZipExtFile is lame
                log.warning(
                    'Using a local memory mapping . Zipfile sux. thx ruby.')
                mmap = AMemoryMapping(start, end, permissions, offset,
                                     major_device, minor_device, inode, pathname=mmap_pathname)
                mmap = LocalMemoryMapping.fromBytebuffer(
                    mmap,
                    mmap_content_file.read())
            # use file mmap when file is too big
            elif end - start > config.MAX_MAPPING_SIZE_FOR_MMAP:
                log.warning('Using a file backed memory mapping. no mmap in memory for this memorymap (%s).' % (mmap_pathname) +
                            ' Search will fail. Buffer is needed.')
                mmap = FileBackedMemoryMapping(mmap_content_file, start, end, permissions, offset,
                                               major_device, minor_device, inode, pathname=mmap_pathname)
            else:
                log.debug('Using a MemoryDumpMemoryMapping. small size')
                mmap = MemoryDumpMemoryMapping(mmap_content_file, start, end, permissions, offset,
                                               major_device, minor_device, inode, pathname=mmap_pathname)
            self.mappings.append(mmap)
        self.mappings.init_config(cpu=self._cpu_bits, os_name=self._os_name)
        return


class LazyProcessMemoryDumpLoader(ProcessMemoryDumpLoader):

    def __init__(self, dumpname, maps_to_load=None, cpu=None, os_name=None):
        self._cpu_bits = cpu
        self._os_name = os_name
        self.dumpname = os.path.normpath(dumpname)
        self.mappings = None
        if not self._is_valid():
            raise ValueError(
                'memory dump not valid for %s ' %
                (self.__class__))
        if maps_to_load is None:
            self._maps_to_load = ['[heap]', '[stack]']
        log.debug('Filter on mapping names: %s ' % (self._maps_to_load))
        return

    def _protected_open_file(self, mmap_fname, mmap_pathname):
        if mmap_pathname is not None and mmap_pathname in self._maps_to_load:
            log.debug('SELECTED: %s' % (mmap_pathname))
            return self._open_file(self.archive, self.filePrefix + mmap_fname)
        else:
            log.debug('IGNORED: %s' % (mmap_pathname))
            # return lambda: (file(os.path.sep.join([self.archive,
            # self.filePrefix+mmap_fname]),'r')
            raise LazyLoadingException(
                os.path.sep.join([self.archive, self.filePrefix + mmap_fname]))
            # TODO FIX with name only, not file()


class KCoreDumpLoader(MemoryDumpLoader):

    """Mapping loader for kernel memory mappings."""

    def isValid(self):
        # debug we need a system map to validate...... probably
        return True

    def getBaseOffset(self, systemmap):
        systemmap.seek(0)
        for l in systemmap.readlines():
            if 'T startup_32' in l:
                addr, d, n = l.split()
                log.info('found base_offset @ %s' % (addr))
                return int(addr, 16)
        return None

    def getInitTask(self, systemmap):
        systemmap.seek(0)
        for l in systemmap.readlines():
            if 'D init_task' in l:
                addr, d, n = l.split()
                log.info('found init_task @ %s' % (addr))
                return int(addr, 16)
        return None

    def getDTB(self, systemmap):
        systemmap.seek(0)
        for l in systemmap.readlines():
            if '__init_end' in l:
                addr, d, n = l.split()
                log.info('found __init_end @ %s' % (addr))
                return int(addr, 16)
        return None

    def loadMappings(self):
        # DEBUG
        #start = 0xc0100000
        start = 0xc0000000
        end = 0xc090d000
        kmap = MemoryDumpMemoryMapping(file(self.dumpname), start, end, permissions='rwx-', offset=0x0,
                                                      major_device=0x0, minor_device=0x0, inode=0x0, pathname=self.dumpname)
        self.mappings = MemoryHandler([kmap], self.dumpname)


class TargetPlatform(interfaces.ITargetPlatform):
    """The guest platform information for the process memory handled by IMemoryHandler.
    Immutable, its characteristics should be set once at creation time.
    """
    WINXP = 'winxp'
    WIN7 = 'win7'
    LINUX = 'linux'

    def __init__(self, mappings):
        if not isinstance(mappings, list):
            raise TypeError("list of IMemoryMapping expected")
        elif len(mappings) == 0:
            raise TypeError("list with at least one IMemoryMapping expected")
        elif not isinstance(mappings[0], interfaces.IMemoryMapping):
            raise TypeError("IMemoryMapping list expected")
        self.__mappings = list(mappings)
        self.__os_name = self._detect_os(self.__mappings)
        self.__cpu_bits = self._detect_cpu(self.__mappings, self.__os_name)
        self.__word_size = self._detect_word_size()
        self.__ptr_size = self._detect_ptr_size()
        self.__ld_size = self._detect_ld_size() # long double
        # win  32 bits, 4,4,8
        # linux 32 bits, 4,4,12
        # linux 64 bits, 8,8,16
        self.__ctypes_proxy = types.reload_ctypes(self.__word_size, self.__ptr_size, self.__ld_size)
        pass

    def get_os_name(self):
        return self.__os_name

    def get_cpu_bits(self):
        return self.__cpu_bits

    def get_target_ctypes(self):
        """Returns the ctypes proxy instance adequate for the target process' platform """
        return self.__ctypes_proxy

    def get_word_size(self):
        return self.__word_size

    def get_word_type(self):
        if self.get_word_size() == 4:
            return self.__ctypes_proxy.c_uint32
        elif self.get_word_size() == 8:
            return self.__ctypes_proxy.c_uint64
        else:
            raise ValueError(
                'platform not supported for word size == %d' %
                (self.get_word_size()))

    def get_word_type_char(self):
        if self.get_word_size() == 4:
            return 'I'
        elif self.get_word_size() == 8:
            return 'Q'
        else:
            raise ValueError(
                'platform not supported for word size == %d' %
                (self.get_word_size()))

    @staticmethod
    def _detect_os(self, mappings):
        """Arch independent way to assess the os of a captured process"""
        linux = winxp = win7 = 0
        for pathname in [m.pathname.lower() for m in mappings
                         if m.pathname is not None and m.pathname != '']:
            if '\\system32\\' in pathname:
                winxp += 1
                win7 += 1
            if 'ntdll.dll' in pathname:
                winxp += 1
                win7 += 1
            elif 'Documents and Settings' in pathname:
                winxp += 1
            elif 'xpsp2res.dll' in pathname:
                winxp += 1
            elif 'SysWOW64' in pathname:
                win7 += 1
            elif '\\wer.dll' in pathname:
                win7 += 1
            elif '[heap]' in pathname:
                linux += 1
            elif '[vdso]' in pathname:
                linux += 1
            elif '/usr/lib/' in pathname:
                linux += 1
            elif '/' == pathname[0]:
                linux += 1
        log.debug(
            'detect_os: scores linux:%d winxp:%d win7:%d' %
            (linux, winxp, win7))
        scores = max(linux, max(winxp, win7))
        if scores == linux:
            return self.LINUX
        elif scores == winxp:
            return self.WINXP
        elif scores == win7:
            return self.WIN7

    @staticmethod
    def _detect_cpu(self, mappings, os_name=None):
        if os_name is None:
            os_name = self._detect_os(mappings)
        cpu = 'unknown'
        if os_name == self.LINUX:
            cpu = self._detect_cpu_arch_elf(mappings)
        elif os_name == self.WINXP or os_name == self.WIN7:
            cpu = self._detect_cpu_arch_pe(mappings)
        return cpu

    @staticmethod
    def _detect_cpu_arch_pe(self, mappings):
        import pefile
        # get the maps with read-only data
        # find the executable image and get the PE header
        pe = None
        for m in mappings:
            # volatility dumps VAD differently than winappdbg
            # we have to look at all mappings
            # if m.permissions != 'r--':
            #    continue
            try:
                head = m.read_bytes(m.start, 0x1000)
                pe = pefile.PE(data=head, fast_load=True)
                # only get the First one that works
                if pe is None:
                    continue
                break
            except pefile.PEFormatError as e:
                pass
        machine = pe.FILE_HEADER.Machine
        arch = pe.OPTIONAL_HEADER.Magic
        if arch == 0x10b:
            return 32
        elif arch == 0x20b:
            return 64
        else:
            raise NotImplementedError('MACHINE is %s' % (pe.e_machine))

    @staticmethod
    def _detect_cpu_arch_elf(self, mappings):
        from haystack.structures.libc.ctypes_elf import struct_Elf_Ehdr
        # find an executable image and get the ELF header
        for m in mappings:
            if 'r-xp' not in m.permissions:
                continue
            try:
                head = m.read_bytes(m.start, 0x40)  # 0x34 really
            except Exception as e:
                log.debug('read_bytes failed '+ str(e))
                continue
            x = struct_Elf_Ehdr.from_buffer_copy(head)
            log.debug('MACHINE:%s pathname:%s' % (x.e_machine, m.pathname))
            if x.e_machine == 3:
                return 32
            elif x.e_machine == 62:
                return 64
            else:
                continue
        raise NotImplementedError('MACHINE has not been found.')

    def _detect_ptr_size(self):
        # by default, we only handle this
        return self.__cpu_bits/8

    def _detect_word_size(self):
        # by default, we only handle this
        return self.__cpu_bits/8

    def _detect_ld_size(self):
        # win  32 bits, 4,4,8
        # linux 32 bits, 4,4,12
        # linux 64 bits, 8,8,16
        if self.__os_name in [self.WINXP,self.WIN7]:
            return 8
        elif (self.__os_name == self.LINUX and self.__word_size == 4):
            return 12
        return 16



def make_config(cpu=None, os_name=None):
    """    """
    if cpu is None:
        #raise ValueError('cpu is None')
        cpu = platform.architecture()[0].split('bit')[0]
    if os_name is None:
        raise ValueError('os_name is None')
        # if linux in sys.platform:
        #    os_name='linux'
        # else:# sys.platform.startswith('win'):
        #    os_name=win7
    if cpu == '32':
        if os_name in ['winxp', 'win7']:
            return make_config_win_32()
        elif os_name == 'linux':
            return make_config_linux_32()
    elif cpu == '64':
        if os_name in ['winxp', 'win7']:
            return make_config_win_64()
        elif os_name == 'linux':
            return make_config_linux_64()
    raise NotImplementedError()


def make_config_win_32():
    """    """
    cfg = TargetPlatform()
    cfg.set_word_size(4, 4, 8)
    return cfg


def make_config_win_64():
    """    """
    cfg = TargetPlatform()
    cfg.set_word_size(8, 8, 8)
    return cfg


def make_config_linux_32():
    """    """
    cfg = TargetPlatform()
    cfg.set_word_size(4, 4, 12)
    return cfg


def make_config_linux_64():
    """    """
    cfg = TargetPlatform()
    cfg.set_word_size(8, 8, 16)
    return cfg


"""Order of attempted loading"""
loaders = [ProcessMemoryDumpLoader, KCoreDumpLoader]


def load(dumpname, cpu=None, os_name=None):
    """Loads a haystack dump."""
    memdump = LazyProcessMemoryDumpLoader(
        os.path.normpath(dumpname),
        cpu=cpu,
        os_name=os_name)
    log.debug('%d dump file loaded' % (len(memdump.getMappings())))
    # excep mmap.error - to much openfile - increase ulimit
    return memdump.getMappings()



