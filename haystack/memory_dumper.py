#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Dumps a process memory mappings to a haystack dump format."""

import logging
import argparse
import ctypes
import os
import pickle
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile

from haystack import dbg
from haystack import memory_mapping
from haystack import argparse_utils

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('dumper')

def archiveTypes(s):
  """Validates TYPE args to check if the dump type is correct."""
  if s not in MemoryDumper.ARCHIVE_TYPES:
    raise ValueError
  return s

class MemoryDumper:
  ''' Dumps a process memory maps to a tgz '''
  ARCHIVE_TYPES = ["dir", "tar","gztar"]
  
  def __init__(self, pid, dest, archiveType="dir", justStack=False, justHeap=False):
    self._pid = pid
    self._dest = os.path.normpath(dest)
    self._archive_type = archiveType
    self._just_stack = justStack
    self._just_heap = justHeap
  
  def getMappings(self):
    """Returns the MemoryMappings."""
    return self.mappings

  def connectProcess(self):
    """Connect the debugguer to the process and gets the memory mappings metadata."""
    self.dbg = dbg.PtraceDebugger()
    self.process = self.dbg.addProcess(self._pid, is_attached=False)
    if self.process is None:
      log.error("Error initializing Process debugging for %d"% self._pid)
      raise IOError
      # ptrace exception is raised before that
    self.mappings = memory_mapping.readProcessMappings(self.process)
    log.debug('mappings read. Dropping ptrace on pid.')
    return

  def dump(self, dest=None):
    """Dumps the source memory mapping to the target dump place."""
    if dest is not None:
      self._dest = os.path.normpath(dest)
    if self._archive_type == "dir":
      self._dump_to_dir()
    else:
      self._dump_to_file()
    return self._dest
    
  def _dump_to_dir(self):
    """Dump memory mappings to files in a directory."""
    if os.path.isfile(self._dest):
      raise TypeError('target is a file. You asked for a directory dump. Please delete the file.')
    if not os.access(self._dest, os.X_OK | os.F_OK ):
      os.mkdir(self._dest)
    self._dump_all_mappings(self._dest)
    self._free_process()
    return 

  def _dump_to_file(self):
    """Dump memory mappings to an archive."""
    if os.path.isdir(self._dest):
      raise TypeError('Target is a dir. You asked for a file dump. Please delete the dir.')
    tmpdir = tempfile.mkdtemp()
    self._dump_all_mappings(tmpdir)
    self._free_process()
    self._make_archive(tmpdir, self._dest)
    return 

  def _dump_all_mappings_winapp(self, destdir):
    # winappdbg
    self.index = file(os.path.join(destdir,'mappings'),'w+')
    # test dump only the heap
    err=0
    memory_maps = self.process.generate_memory_snaphost() 
    for mbi in memory_maps:
      #TODO
      try:
        self._dump_mapping(m, destdir)
      except IOError,e:
        err+=1
        log.warning(e)
        pass # no se how to read windows
    log.debug('%d mapping in error, destdir: %s'%(err, destdir))
    self.index.close()
    return

  def _dump_all_mappings(self, destdir):
    """Iterates on all mappings and dumps them to file."""
    self.index = file(os.path.join(destdir,'mappings'),'w+')
    # test dump only the heap
    err=0
    #print '\n'.join([str(m) for m in self.mappings])
    for m in self.mappings:
      try:
        self._dump_mapping(m, destdir)
      except IOError,e:
        err+=1
        log.warning(e)
        pass # no se how to read windows
    log.debug('%d mapping in error, destdir: %s'%(err, destdir))
    self.index.close()
    return
  
  def _free_process(self):
    """continue() the process."""
    self.process.cont()
    self.dbg.deleteProcess(process=self.process)
    self.dbg.quit()
    return 
    

  def _dump_mapping(self, m, tmpdir):
    """Dump one mapping to one file in one tmpdir."""
    log.debug('Dumping %s to %s'%(m,tmpdir))
    # dump files to tempdir
    mname = "%s-%s" % (dbg.formatAddress(m.start), dbg.formatAddress(m.end))
    mmap_fname = os.path.join(tmpdir, mname)
    # we are dumping the memorymap content
    if self._just_heap or self._just_stack: #dump heap and/or stack
      if ( (self._just_heap  and m.pathname == '[heap]') or 
             (self._just_stack and m.pathname == '[stack]') ) :
        log.debug('Dumping the memorymap content')
        with open(mmap_fname,'wb') as mmap_fout:
          mmap_fout.write(m.mmap().getByteBuffer())
    else: #dump all the memory maps
      log.debug('Dumping the memorymap content')
      with open(mmap_fname,'wb') as mmap_fout:
        mmap_fout.write(m.mmap().getByteBuffer())
    #dump all the memory maps metadata
    log.debug('Dumping the memorymap metadata')
    self.index.write('%s\n'%(m) )
    return 

  def _make_archive(self, srcdir, name):
    """Make an archive file."""
    log.debug('Making a archive ')
    tmpdir = tempfile.mkdtemp()
    tmpname = os.path.join(tmpdir, os.path.basename(name))
    log.debug('running shutil.make_archive')
    archive = shutil.make_archive(tmpname, self._archive_type, srcdir) 
    shutil.move(archive, name )
    shutil.rmtree(tmpdir)
    shutil.rmtree(srcdir)
    return


def dump(pid, outfile, typ="dir", heapOnly=False, stackOnly=False):
  """Dumps a process memory mappings to Haystack dump format."""
  dumper = MemoryDumper(pid, outfile, typ, stackOnly, heapOnly )
  dumper.connectProcess()
  destname = dumper.dump()
  log.info('Process %d memory mappings dumped to file %s'%(dumper._pid, destname))
  return destname

def _dump(opt):
  """Dumps a process memory mappings to Haystack dump format."""
  return dump(opt.pid, opt.dumpname, opt.type, opt.stack, opt.heap)

def argparser():
  dump_parser = argparse.ArgumentParser(prog='memory_dumper', description="dump a pid's memory to file.")
  dump_parser.add_argument('pid', type=int, action='store', help='Target PID.')
  dump_parser.add_argument('--heap', action='store_const', const=True , help='Restrict dump to the heap.')
  dump_parser.add_argument('--stack', action='store_const', const=True , help='Restrict dump to the stack.')
  dump_parser.add_argument('--type',  type=archiveTypes, action='store' , default="dir", 
            help='Dump in "gztar","tar" or "dir" format. Defaults to "dir".')
  dump_parser.add_argument('dumpname', type=argparse_utils.writeable, action='store', help='The dump name.')
  dump_parser.set_defaults(func=_dump)  

  return dump_parser

def main(argv):
  logging.basicConfig(level=logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
