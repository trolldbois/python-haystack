#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import argparse, ctypes, os, pickle, time, sys
import tarfile, zipfile
import tempfile, shutil

import dbg
import memory_mapping

log = logging.getLogger('dumper')


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
      #except Exception,e:
      except IOError,e:
        err+=1
        print e
        pass # no se how to read windows
    log.warning('%d mapping in error, tmpdir: %s'%(err, tmpdir))
    self.index.close()
    #continue() the process
    self.process.cont()
    self.dbg.deleteProcess(process=self.process)
    # 
    log.debug('Making a archive ')
    archive_name = os.path.normpath(self.args.dumpfile.name)
    self.archive(tmpdir, archive_name)
    shutil.rmtree(tmpdir)
    log.debug('tmpdir is %s'%(tmpdir)) 
    log.debug('Dumped to %s'%(archive_name))
    return archive_name
      
  def dump(self, m, tmpdir):
    log.debug('Dumping %s to %s'%(m,tmpdir))
    # dump files to tempdir
    mname = "%s-%s" % (dbg.formatAddress(m.start), dbg.formatAddress(m.end))
    mmap_fname = os.path.join(tmpdir, mname)
    # we are dumping the memorymap content
    if ((self.args.heap or self.args.stack) and
      m.pathname not in ['[heap]','[stack]'] ): # restrict dump
      pass
    else:
      log.debug('Dumping the memorymap content')
      with open(mmap_fname,'wb') as mmap_fout:
        mmap_fout.write(m.mmap().getByteBuffer())
    log.debug('Dumping the memorymap metadata')
    self.index.write('%s\n'%(m) )
    return 

  def archive(self, srcdir, name):
    tmpdir = tempfile.mkdtemp()
    tmpname = os.path.join(tmpdir, os.path.basename(name))
    log.debug('running shutil.make_archive')
    archive = shutil.make_archive(tmpname, 'tar', srcdir) #gztar
    shutil.move(archive, name )
    shutil.rmtree(tmpdir ) # not working ?


class Dummy:
  pass

def dumpToFile(pid, outfile, heapOnly=False, stackOnly=False):
  opt = Dummy()
  opt.pid = int(pid)
  opt.dumpfile = file(outfile,'wb')
  opt.heap = heapOnly
  opt.stack = stackOnly
  return dump(opt)

def dump(opt):
  dumper = MemoryDumper(opt)
  dumper.initPid()
  out = dumper.dumpMemfile()
  log.debug('process %d dumped to file %s'%(opt.pid, os.path.normpath(opt.dumpfile.name)))
  return os.path.normpath(opt.dumpfile.name)

def argparser():
  dump_parser = argparse.ArgumentParser(prog='memory_dumper', description="dump a pid's memory to file")
  dump_parser.add_argument('pid', type=int, action='store', help='Target PID')
  dump_parser.add_argument('dumpfile', type=argparse.FileType('wb'), action='store', help='The dump file')
  dump_parser.add_argument('--heap', action='store_const', const=True , help='Restrict dump to the heap')
  dump_parser.add_argument('--stack', action='store_const', const=True , help='Restrict dump to the stack')
  dump_parser.set_defaults(func=dump)  

  return dump_parser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
