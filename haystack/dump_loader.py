#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This module offers several classes in charge of loading the memory
mapping dumps into a MemoryMappings list of MemoryMapping, given a
previously saved format ( file, archive, ... ).
Basically MemoryMappings are in archive of all the _memory_handler dumped to
file + a special '_memory_handler' index file that give all metadata about
thoses _memory_handler.

Classes:
 - MemoryDumpLoader:    abstract loader for a memory dump loader
 - ProcessMemoryDumpLoader: handles memory load from several recognized
        format.
 - KCoreDumpLoader: Mapping loader for kernel memory _memory_handler dumps.

Functions:
 - load: load MemoryMappings from the source dumpname.

"""

import logging
import zipfile  # relatively useless

import os

import haystack
from haystack.abc import interfaces
from haystack.mappings.base import MemoryHandler, AMemoryMapping
from haystack.mappings.file import FileBackedMemoryMapping
from haystack.mappings.file import FilenameBackedMemoryMapping
from haystack.mappings.file import LocalMemoryMapping
from haystack.mappings.file import MemoryDumpMemoryMapping
from haystack.target import TargetPlatform

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


class MemoryDumpLoader(interfaces.IMemoryLoader):
    """
    Abstract interface to a memory dump loader.

    isValid and loadMapping should be implemented.
    """

    def __init__(self, dumpname, cpu=None, os_name=None):
        self._cpu_bits = cpu
        self._os_name = os_name
        self.dumpname = os.path.normpath(dumpname)
        self._memory_handler = None
        if not self._is_valid():
            raise ValueError(
                'memory dump not valid for %s ' %
                (self.__class__))

    def make_memory_handler(self):
        if self._memory_handler is None:
            self._load_mappings()
        self._memory_handler.reset_mappings()
        return self._memory_handler

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
            log.error("_test_dir returned False")
        else:
            raise IOError('%s is not a directory' % self.dumpname)
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
        """Loads the _memory_handler content from the dump to a MemoryMappings.

        If an underlying file containing a memory dump does not exists, still
        create a MemoryMap for metadata purposes.
        If the memory map is > _target_platform.MAX_MAPPING_SIZE_FOR_MMAP, use a slow FileBackedMemoryMapping.
        Else, load the mapping in memory.
        """
        self._load_metadata()
        self._load_memory_mappings()  # set self._memory_handler
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
        _mappings = []
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
                _mappings.append(mmap)
                continue
            # except ValueError,e: # explicit non-loading
            #    log.debug('Ignore useless file : %s'%(e))
            #    mmap = MemoryMapping(start, end, permissions, offset,
            #                                                    major_device, minor_device, inode,pathname=mmap_pathname)
            #    self._memory_handler.append(mmap)
            #    continue
            except LazyLoadingException as e:
                mmap = FilenameBackedMemoryMapping(e._filename, start, end, permissions, offset,
                                                   major_device, minor_device, inode, pathname=mmap_pathname)
                _mappings.append(mmap)
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
            elif end - start > haystack.MAX_MAPPING_SIZE_FOR_MMAP:
                log.warning('Using a file backed memory mapping. no mmap in memory for this memorymap (%s).' % (mmap_pathname) +
                            ' Search will fail. Buffer is needed.')
                mmap = FileBackedMemoryMapping(mmap_content_file.name, start, end, permissions, offset,
                                               major_device, minor_device, inode, pathname=mmap_pathname)
            else:
                # log.debug('Using a MemoryDumpMemoryMapping. small size')
                # mmap = MemoryDumpMemoryMapping(mmap_content_file, start, end, permissions, offset,
                log.debug('Always use FilenameBackedMemoryMapping. small size')
                mmap = FilenameBackedMemoryMapping(mmap_content_file.name, start, end, permissions, offset,
                                               major_device, minor_device, inode, pathname=mmap_pathname)
            _mappings.append(mmap)
        _target_platform = TargetPlatform(_mappings, cpu_bits=self._cpu_bits, os_name=self._os_name)
        self._memory_handler = MemoryHandler(_mappings, _target_platform, self.dumpname)
        return


class LazyProcessMemoryDumpLoader(ProcessMemoryDumpLoader):

    def __init__(self, dumpname, maps_to_load=None, cpu=None, os_name=None):
        self._cpu_bits = cpu
        self._os_name = os_name
        self.dumpname = os.path.normpath(dumpname)
        self._memory_handler = None
        if not self._is_valid():
            raise ValueError(
                'memory dump not valid for %s ' %
                (self.__class__))
        if maps_to_load is None:
            self._maps_to_load = ['[heap]', '[stack]']
        log.debug('Filter on mapping names: %s ' % self._maps_to_load)
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

class VeryLazyProcessMemoryDumpLoader(LazyProcessMemoryDumpLoader):
    """
    Always use a filename backed memory mapping.
    """
    def _load_memory_mappings(self):
        """ make the python objects"""
        _mappings = []
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
            fname = os.path.sep.join([self.dumpname, mmap_fname])
            mmap = FilenameBackedMemoryMapping(fname, start, end, permissions, offset,
                                               major_device, minor_device, inode, pathname=mmap_pathname)
            _mappings.append(mmap)
        _target_platform = TargetPlatform(_mappings, cpu_bits=self._cpu_bits, os_name=self._os_name)
        self._memory_handler = MemoryHandler(_mappings, _target_platform, self.dumpname)
        self._memory_handler.reset_mappings()
        return

def load(dumpname, cpu=None, os_name=None):
    """Loads a haystack dump."""
    memdump = VeryLazyProcessMemoryDumpLoader( # LazyProcessMemoryDumpLoader(
        os.path.normpath(dumpname),
        cpu=cpu,
        os_name=os_name)
    log.debug('%d dump file loaded' % len(memdump.make_memory_handler()))
    # excep mmap.error - to much openfile - increase ulimit
    return memdump.make_memory_handler()



