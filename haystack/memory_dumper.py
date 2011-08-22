#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, ctypes, os, pickle, time, sys
import tarfile
import tempfile, shutil


import dbg
import memory_mapping

log = logging.getLogger('dumper')

class Dummy:
  pass

class MemoryDumper:
  ''' Dumps a process memory maps to a tgz '''
  def __init__(self,args):
    self.args = args
  
  def getMappings(self):
    return self.mappings

  def initPid(self):
    self.dbg = dbg.PtraceDebugger()
    self.process = self.dbg.addProcess(self.args.pid, is_attached=False)
    if self.process is None:
      log.error("Error initializing Process debugging for %d"% self.args.pid)
      raise IOError
      # ptrace exception is raised before that
    self.mappings = memory_mapping.readProcessMappings(self.process)
    log.debug('mappings read. Dropping ptrace on pid.')
    return
    
  def dumpMemfile(self):
    tmpdir = tempfile.mkdtemp()
    self.index = file(os.path.join(tmpdir,'mappings'),'w+')
    # test dump only the heap
    err=0
    for m in self.mappings:
      try:
        self.dump(m, tmpdir)
      except Exception,e:
        err+=1
        pass # no se how to read windows
    log.warning('%d mapping in error'%err)
    self.index.close()
    #continue() the process
    self.process.cont()
    self.dbg.deleteProcess(process=self.process)
    # 
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
    mname = "%s-%s" % (dbg.formatAddress(m.start), dbg.formatAddress(m.end))
    mmap_fname = os.path.join(tmpdir, mname)
    # we are dumping the memorymap content
    log.debug('Dumping the memorymap content')
    with open(mmap_fname,'wb') as mmap_fout:
      mmap_fout.write(m.mmap().getByteBuffer())
    log.debug('Dumping the memorymap metadata')
    self.index.write('%s,%s\n'%(mname, m.pathname))
    return 

  def archive(self, srcdir, name):
    tmpdir = tempfile.mkdtemp()
    tmpname = os.path.join(tmpdir, os.path.basename(name))
    log.debug('running shutil.make_archive')
    archive = shutil.make_archive(tmpname, 'gztar', srcdir)
    shutil.move(archive, name )
    shutil.rmtree(tmpdir ) # not working ?



class MemoryDumpLoader:
  ''' Loads a memory dump done by MemoryDumper.
  It's basically a tgz of all memorymaps '''
  def __init__(self, dumpfile):
    self.dumpfile = dumpfile
    if not self.isValid():
      raise ValueError('memory dump not valid for %s '%(self.__class__))
    self.loadMappings()
  def getMappings(self):
    return self.mappings
  def loadMappings(self):
    raise NotImplementedError()
    

class ProcessMemoryDumpLoader(MemoryDumpLoader):

  def isValid(self):
    try :
      self.archive = tarfile.open(None,'r', self.dumpfile)
      members = self.archive.getnames() # get the ./away
      if './mappings' not in members:
        log.error('no mappings index file in the archive.')
        return False
      self.mmaps = [ m for m in members if m.startswith('./0x')]
      if len(self.mmaps)>0:
        return True
    except tarfile.ReadError,e:
      return False
        
  def loadMappings(self):
    mappingsFile = self.archive.extractfile('./mappings')
    self.metalines = [l.strip().split(',') for l in mappingsFile.readlines()]
    self.mappings = []
    #for mmap_fname in self.mmaps:
    for mmap_fname, mmap_pathname in self.metalines:
      start,end = mmap_fname.split('-') # get the './' away
      start,end = int(start,16),int(end,16 )
      log.debug('Loading %s - %s'%(mmap_fname, mmap_pathname))
      mmap_content_file = self.archive.extractfile('./'+mmap_fname)
      if end-start > 10000000: # use file mmap when file is too big
        log.warning('Using a file backed memory mapping. no mmap in memory for this memorymap. Search will fail. Buffer is needed.')
        mmap = memory_mapping.FileBackedMemoryMapping(mmap_content_file, start, end, permissions='rwx-', offset=0x0, 
                                major_device=0x0, minor_device=0x0, inode=0x0,pathname=mmap_pathname)
      else:      
        log.debug('Using a MemoryDumpMemoryMapping. small size')
        mmap = memory_mapping.MemoryDumpMemoryMapping(mmap_content_file, start, end, permissions='rwx-', offset=0x0, 
                                major_device=0x0, minor_device=0x0, inode=0x0,pathname=mmap_pathname)
      self.mappings.append(mmap)
    return    


class KCoreDumpLoader(MemoryDumpLoader):
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
    kmap = memory_mapping.MemoryDumpMemoryMapping(self.dumpfile, start, end, permissions='rwx-', offset=0x0, 
            major_device=0x0, minor_device=0x0, inode=0x0, pathname=self.dumpfile.name)
    self.mappings = [kmap]




def dump(opt):
  dumper = MemoryDumper(opt)
  dumper.initPid()
  out = dumper.dumpMemfile()
  log.debug('process %d dumped to file %s'%(opt.pid, opt.dumpfile.name))
  return opt.dumpfile.name

def _load(opt):
  return load(opt.dumpfile,opt.lazy)

loaders = [ProcessMemoryDumpLoader,KCoreDumpLoader]

def load(dumpfile,lazy=True):
  try:
    memdump = ProcessMemoryDumpLoader(dumpfile)
    log.debug('%d dump file loaded'%(len(memdump.getMappings()) ))
    #if log.isEnabledFor(logging.DEBUG):
      #for m in memdump.getMappings(): # will mmap() all
      #  log.debug('%s - len(%d) rlen(%d)' %(m, (m.end-m.start), len(m.mmap())) )
  except ValueError,e:
    log.warning(e)
    #log.warning('trying a KCore')
    #last chance
    #memdump = KCoreDumpLoader(dumpfile)
    raise e
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
  logging.basicConfig(level=logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
