import mmap, logging
import os, time

# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# local
from memory_mapping import MemoryDumpMemoryMapping , readProcessMappings

log = logging.getLogger('mapper')



class MemoryMapper:
  def __init__(self, args):
    # args are checked by the parser
    if not (args.pid is None):
      mappings = self.initPid(args)
    elif not (args.memfile is None):
      mappings = self.initMemfile(args)
    self.mappings = mappings
    return
  
  def getMappings(self):
    return self.mappings
    
  def initMemfile(self,args):
    mem = MemoryDumpMemoryMapping(args.memfile, 0, os.fstat(args.memfile.fileno()).st_size) ## is that valid ?
    mappings=[mem]
    return mappings

  def initPid(self, args):
    dbg = PtraceDebugger()
    process = dbg.addProcess(args.pid, is_attached=False)
    if process is None:
      log.error("Error initializing Process debugging for %d"% args.pid)
      raise IOError
      # ptrace exception is raised before that
    tmp = readProcessMappings(process)
    mappings=[]
    remains=[]
    t0=time.time()
    for m in tmp :
      if hasattr(args,'mmap') and args.mmap:
        ### mmap memory in local space
        m.mmap()
        log.debug('mmap() : %d'%(len(m.local_mmap)))
      if ( m.pathname == '[heap]' or 
           m.pathname == '[vdso]' or
           m.pathname == '[stack]' or
           m.pathname is None ):
        mappings.append(m)
        continue
      remains.append(m)
    #tmp = [x for x in remains if not x.pathname.startswith('/')] # delete memmapped dll
    tmp=remains
    tmp.sort(key=lambda x: x.start )
    tmp.reverse()
    mappings.extend(tmp)
    mappings.reverse()
    if hasattr(args,'mmap') and args.mmap:
      ### mmap done, we can release process...
      process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))
    return mappings
