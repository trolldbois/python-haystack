import logging
import argparse, os, pickle, time, sys


import model 

# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# local
from memory_mapping import MemoryDumpMemoryMapping , readProcessMappings
import memory_mapping

log = logging.getLogger('mapper')



class MemoryDumper:
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
    return
    
  def dumpMemfile(self):
    # test dump only the heap
    for m in self.mappings:
      if m.pathname != '[heap]':
        continue
      m.mmap()
      return self.dump(m)
  
  def dump(self, m):
    mmap = pickle.dump(m, self.args.output)
    return self.args.output.name

def dump(opt):
  dumper = MemoryDumper(opt)
  dumper.initPid()
  print '\n'.join(str(dumper.mappings).split(','))
  out = dumper.dumpMemfile()
  print out

def load(dumpfile):
  memdump = pickle.load(dumpfile)
  return memdump

def argparser():
  rootparser = argparse.ArgumentParser(prog='memory_dumper', description='Dump process memory.')
  rootparser.add_argument('pid', type=int, action='store', help='Target PID')
  rootparser.add_argument('output', type=argparse.FileType('wb'), action='store', help='Target PID')
  rootparser.set_defaults(func=dump)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
