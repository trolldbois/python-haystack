import ctypes, struct, mmap, logging
# local
from memory_mapping import MemoryDumpMemoryMapping 
# TODO check ctypes_tools.bytes2array in ptrace

log = logging.getLogger('filememdump')


# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# ptrace fork
from memory_mapping import readProcessMappings
import os, time
def getDTB(systemmap):
  systemmap.seek(0)
  for l in systemmap.readlines():
    if '__init_end' in l:
      addr,d,n = l.split()
      log.info('found __init_end @ %s'%(addr))
      return int(addr,16)
  return None


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
    log.debug('memdump initialised %s'%(mappings[0]))
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
      if args.mmap:
        ### mmap memory in local space
        m.mmap()
        #log.warning('mmap() : %d'%(len(m.local_mmap)))
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
    if mmap:
      ### mmap done, we can release process...
      process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))
    return mappings
