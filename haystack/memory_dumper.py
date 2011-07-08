#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, ctypes, os, pickle, time, sys


import model 

# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# local
from memory_mapping import MemoryDumpMemoryMapping, FileMemoryMapping , readProcessMappings
from . import memory_mapping

log = logging.getLogger('dumper')



class MemoryDumper:
  ''' Dumps a process memory maps to a tgz '''
  def __init__(self,args):
    self.args = args
  
  def getMappings(self):
    return self.mappings

  def initPid(self):
    dbg = PtraceDebugger()
    process = dbg.addProcess(self.args.pid, is_attached=False)
    if process is None:
      log.error("Error initializing Process debugging for %d"% self.args.pid)
      raise IOError
      # ptrace exception is raised before that
    self.mappings = readProcessMappings(process)
    log.debug('mappings read.')
    return
    
  def dumpMemfile(self):
    import tempfile
    tmpdir = tempfile.mkdtemp()
    # test dump only the heap
    for m in self.mappings:
      self.dump(m, tmpdir)
    log.debug('Making a archive ')
    archive_name = os.path.normpath(self.args.dumpfile.name)
    self.archive(tmpdir, archive_name)
    #shutil.rmtree(tmpdir)
    log.debug('tmpdir is %s'%(tmpdir)) 
    log.debug('Dumped to %s'%(archive_name))
    return archive_name
      
  def dump(self, m, tmpdir):
    log.debug('Dumping %s to %s'%(m,tmpdir))
    # dump files to tempdir
    mmap_fname = "0x%lx-%s" % (m.start, memory_mapping.formatAddress(m.end))
    mmap_fname = os.path.join(tmpdir, mmap_fname)
    # we are dumping the memorymap content
    m.mmap()
    log.debug('Dumping the memorymap content')
    with open(mmap_fname,'wb') as mmap_fout:
      mmap_fout.write(m.local_mmap)
    log.debug('Dumping the memorymap metadata')
    with open(mmap_fname+'.pickled','w') as mmap_fout:
      pickle.dump(m, mmap_fout)
    return 

  def archive(self, srcdir, name):
    import tempfile, shutil
    tmpdir = tempfile.mkdtemp()
    tmpname = os.path.join(tmpdir, os.path.basename(name))
    log.debug('running shutil.make_archive')
    archive = shutil.make_archive(tmpname, 'gztar', srcdir)
    shutil.move(archive, name )
    shutil.rmtree(tmpdir)




class MemoryDumpLoader:
  ''' Loads a memory dump done by MemoryDumper.
  It's basically a tgz of all memorymaps '''
  def __init__(self, dumpfile):
    self.dumpfile = dumpfile
    self.loadMappings()
  
  def loadMappings(self):
    import tarfile
    self.archive = tarfile.open(None,'r', self.dumpfile)
    #self.archive.list()
    members = self.archive.getnames()
    mmaps = [ (m,m+'.pickled') for m in members if m+'.pickled' in members]
    self.mappings = []
    for content,md in mmaps:
      mmap = pickle.load(self.archive.extractfile(md))
      log.debug('Loading %s'%(mmap))
      mmap_content = self.archive.extractfile(content).read()
      # use that or mmap, anyway, we need to convert to ctypes :/ that costly
      mmap.local_mmap = model.bytes2array(mmap_content, ctypes.c_ubyte)
      self.mappings.append(mmap)
    
  def getMappings(self):
    return self.mappings

class LazyMemoryDumpLoader(MemoryDumpLoader):
  def loadMappings(self):
    import tarfile
    self.archive = tarfile.open(None,'r', self.dumpfile)
    #self.archive.list()
    members = self.archive.getnames()
    mmaps = [ (m,m+'.pickled') for m in members if m+'.pickled' in members]
    self.mappings = []
    for content,md in mmaps:
      mmap = pickle.load(self.archive.extractfile(md))
      log.debug('Lazy Loading %s'%(mmap))
      mmap_file = self.archive.extractfile(content)
      self.mappings.append(FileMemoryMapping(mmap, mmap_file))
      #self.mappings.append(memory_mapping.getFileBackedMemoryMapping(mmap, mmap_file))


def dump(opt):
  dumper = MemoryDumper(opt)
  dumper.initPid()
  #print '\n'.join(str(dumper.mappings).split(','))
  out = dumper.dumpMemfile()
  log.debug('process %d dumped to file %s'%(opt.pid, opt.dumpfile.name))
  return opt.dumpfile.name

def _load(opt):
  return load(opt.dumpfile,opt.lazy)

def load(dumpfile,lazy=True):
  if lazy:
    memdump = LazyMemoryDumpLoader(dumpfile)
  else:  
    memdump = MemoryDumpLoader(dumpfile)
    log.debug('%d dump file loaded'%(len(memdump.getMappings()) ))
    for m in memdump.getMappings():
      log.debug('%s - len(%d) rlen(%d)' %(m, (m.end-m.start), len(m.local_mmap)) )    
  return memdump.getMappings()

def argparser():
  rootparser = argparse.ArgumentParser(prog='memory_dumper', description='Dump process memory.')
  subparsers = rootparser.add_subparsers(help='sub-command help')

  dump_parser = subparsers.add_parser('dump', help="dump a pid's memory to file")
  dump_parser.add_argument('pid', type=int, action='store', help='Target PID')
  dump_parser.add_argument('dumpfile', type=argparse.FileType('wb'), action='store', help='The dump file')
  dump_parser.set_defaults(func=dump)  

  load_parser = subparsers.add_parser('load', help='search help')
  load_parser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='The dump file')
  load_parser.add_argument('--lazy', action='store_const', const=True , help='Lazy load')
  load_parser.set_defaults(func=_load)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
