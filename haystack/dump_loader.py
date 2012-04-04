#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""This module offers several classes in charge of loading the memory 
mapping dumps into a MemoryMappings list of MemoryMapping, given a 
previously saved format ( file, archive, ... ). 
Basically MemoryMappings are in archive of all the mappings dumped to 
file + a special 'mappings' index file that give all metadata about 
thoses mappings.

Classes:
 - MemoryDumpLoader:  abstract loader for a memory dump loader
 - ProcessMemoryDumpLoader: handles memory load from several recognized 
    format.
 - KCoreDumpLoader: Mapping loader for kernel memory mappings dumps.

Functions:
 - load: load MemoryMappings from the source dumpname.

"""

import logging
import argparse
import os
import sys
import tarfile
import zipfile # relatively useless

from haystack.config import Config
from haystack import utils
from haystack import memory_mapping
from haystack import argparse_utils

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

class MemoryDumpLoader:
  ''' Abstract interface to a memory dump loader.
  
  isValid and loadMapping should be implemented.
  '''
  def __init__(self, dumpname):
    self.dumpname = os.path.normpath(dumpname)
    self.mappings = None
    if not self._is_valid():
      raise ValueError('memory dump not valid for %s '%(self.__class__))

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
      if self._test_dir() : 
        self._open_archive = lambda archive: archive
        self._list_names = os.listdir
        self._open_file = lambda archive,name: file( os.path.sep.join([archive,name]),'rb')
        return True
    return False

  def _test_dir(self):
    try :
      self.archive = self.dumpname
      members = os.listdir(self.archive)
      if self.indexFilename not in members:
        log.error('no mappings index file in the directory.')
        return False
      self.filePrefix=''
      self.mmaps = [ m for m in members if '-0x' in m ]
      if len(self.mmaps)>0:
        return True
    except OSError,e:
      log.info('Not a valid directory')
    return False

  def _protected_open_file(self, mmap_fname, mmap_pathname):
    return self._open_file(self.archive, self.filePrefix+mmap_fname)
  
  def _load_mappings(self):
    """Loads the mappings content from the dump to a MemoryMappings.
    
    If an underlying file containing a memory dump does not exists, still
    create a MemoryMap for metadata purposes.
    If the memory map is > Config.MAX_MAPPING_SIZE_FOR_MMAP, use a slow FileBackedMemoryMapping.
    Else, load the mapping in memory.
    """
    mappingsFile = self._open_file(self.archive, self.indexFilename)
    self.metalines = []
    for l in mappingsFile.readlines():
      fields = l.strip().split(' ')
      if '' in fields:
        fields.remove('')
      self.metalines.append( ( fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], ' '.join(fields[6:]) )  )
    # test if x32 or x64
    if len(fields[0]) > 10:
      log.info('x64 arch dump detected')
      Config.WORDSIZE = 8
    self_mappings = []
    for _start, _end, permissions, offset, devices, inode, mmap_pathname in self.metalines:
      start,end = int(_start,16),int(_end,16 )
      offset = int(offset,16)
      inode = int(inode)
      #rebuild filename
      mmap_fname = "%s-%s" % (utils.formatAddress(start), utils.formatAddress(end))
      # get devices nums
      major_device, minor_device = devices.split(':')
      major_device = int(major_device,16)
      minor_device = int(minor_device,16)
      log.debug('Loading %s - %s'%(mmap_fname, mmap_pathname))
      # open the file in the archive
      try:
        mmap_content_file = self._protected_open_file(mmap_fname, mmap_pathname)
      except (IOError, KeyError), e:
        log.debug('Ignore absent file : %s'%(e))
        mmap = memory_mapping.MemoryMapping( start, end, permissions, offset, 
                                major_device, minor_device, inode,pathname=mmap_pathname)
        self_mappings.append(mmap)
        continue
      #except ValueError,e: # explicit non-loading
      #  log.debug('Ignore useless file : %s'%(e))
      #  mmap = memory_mapping.MemoryMapping(start, end, permissions, offset, 
      #                          major_device, minor_device, inode,pathname=mmap_pathname)
      #  self_mappings.append(mmap)
      #  continue
      except LazyLoadingException,e: 
        mmap = memory_mapping.FilenameBackedMemoryMapping(e._filename, start, end, permissions, offset, 
                                major_device, minor_device, inode,pathname=mmap_pathname)
        self_mappings.append(mmap)
        continue
      
      if isinstance(self.archive, zipfile.ZipFile): # ZipExtFile is lame
        log.warning('Using a local memory mapping . Zipfile sux. thx ruby.')
        mmap = memory_mapping.MemoryMapping( start, end, permissions, offset, 
                                major_device, minor_device, inode,pathname=mmap_pathname)
        mmap = memory_mapping.LocalMemoryMapping.fromBytebuffer(mmap, mmap_content_file.read())
      elif end-start > Config.MAX_MAPPING_SIZE_FOR_MMAP: # use file mmap when file is too big
        log.warning('Using a file backed memory mapping. no mmap in memory for this memorymap (%s).'%(mmap_pathname)+
                    ' Search will fail. Buffer is needed.')
        mmap = memory_mapping.FileBackedMemoryMapping(mmap_content_file, start, end, permissions, offset, 
                                major_device, minor_device, inode,pathname=mmap_pathname)
      else:
        log.debug('Using a MemoryDumpMemoryMapping. small size')
        mmap = memory_mapping.MemoryDumpMemoryMapping(mmap_content_file, start, end, permissions, offset, 
                                major_device, minor_device, inode,pathname=mmap_pathname)
      self_mappings.append(mmap)
    self.mappings = memory_mapping.Mappings(self_mappings, self.dumpname)
    return    


class LazyProcessMemoryDumpLoader(ProcessMemoryDumpLoader):
  def __init__(self, dumpname, maps_to_load=None):
    self.dumpname = os.path.normpath(dumpname)
    self.mappings = None
    if not self._is_valid():
      raise ValueError('memory dump not valid for %s '%(self.__class__))
    if maps_to_load is None:
      self._maps_to_load = ['[heap]', '[stack]']
    return
    
  def _protected_open_file(self, mmap_fname, mmap_pathname):
    log.debug( '%s %s '%(mmap_pathname, self._maps_to_load))
    if mmap_pathname is not None and mmap_pathname in self._maps_to_load:
      log.debug( 'SELECTED')
      return self._open_file(self.archive, self.filePrefix+mmap_fname)
    else:
      log.debug( 'IGNORED')
      #return lambda: (file(os.path.sep.join([self.archive, self.filePrefix+mmap_fname]),'r')
      raise LazyLoadingException( os.path.sep.join([self.archive, self.filePrefix+mmap_fname]))
      # TODO FIX with name only, not file()


class KCoreDumpLoader(MemoryDumpLoader):
  """Mapping loader for kernel memory mappings."""
  def isValid(self):
    # debug we need a system map to validate...... probably
    return True
    
  def getBaseOffset(self,systemmap):
    systemmap.seek(0)
    for l in systemmap.readlines():
      if 'T startup_32' in l:
        addr,d,n = l.split()
        log.info('found base_offset @ %s'%(addr))
        return int(addr,16)
    return None

  def getInitTask(self,systemmap):
    systemmap.seek(0)
    for l in systemmap.readlines():
      if 'D init_task' in l:
        addr,d,n = l.split()
        log.info('found init_task @ %s'%(addr))
        return int(addr,16)
    return None
    
  def getDTB(self,systemmap):
    systemmap.seek(0)
    for l in systemmap.readlines():
      if '__init_end' in l:
        addr,d,n = l.split()
        log.info('found __init_end @ %s'%(addr))
        return int(addr,16)
    return None
    
  def loadMappings(self):
    #DEBUG
    #start = 0xc0100000
    start = 0xc0000000
    end = 0xc090d000
    kmap = memory_mapping.MemoryDumpMemoryMapping(file(self.dumpname), start, end, permissions='rwx-', offset=0x0, 
            major_device=0x0, minor_device=0x0, inode=0x0, pathname=self.dumpname)
    self.mappings = memory_mapping.Mappings([kmap], self.dumpname)


"""Order of attempted loading"""
loaders = [ProcessMemoryDumpLoader,KCoreDumpLoader]

def load(dumpname):
  """Loads a haystack dump."""
  try:
    memdump = LazyProcessMemoryDumpLoader( os.path.normpath(dumpname) )
    log.debug('%d dump file loaded'%(len(memdump.getMappings()) ))
  except IndexError,e: ### ValueError,e:
    log.warning(e)
    raise e
  return memdump.getMappings()

def _heap(opt):
  """find  the heap in a haystack dump."""
  mappings = load(opt.dumpname)
  from haystack.reverse import libc as linux
  from haystack.reverse import win32
  for m in mappings:
    pass
  

def argparser():
  heap_parser = argparse.ArgumentParser(prog='dump_loader', description='load dumped process memory.')
  heap_parser.add_argument('dumpname', type=argparse_utils.readable, action='store', help='The dump file')
  heap_parser.set_defaults(func=_heap)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
