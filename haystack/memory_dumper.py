import logging
import argparse, os, pickle, time, sys


import model 

# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# local
from memory_mapping import MemoryDumpMemoryMapping , readProcessMappings
import memory_mapping

log = logging.getLogger('dumper')



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
    log.debug('mappings read.')
    return
    
  def dumpMemfile(self):
    import tempfile
    tmpdir = tempfile.mkdtemp()
    # test dump only the heap
    for m in self.mappings:
      if m.pathname != '[heap]':
        continue
      self.dump(m, tmpdir)
    log.debug('Making a archive ')
    archive_name = os.path.normpath(self.args.output.name)
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

def dump(opt):
  dumper = MemoryDumper(opt)
  dumper.initPid()
  #print '\n'.join(str(dumper.mappings).split(','))
  out = dumper.dumpMemfile()

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
  logging.basicConfig(level=logging.DEBUG)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
