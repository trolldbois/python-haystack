#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Search for a known structure type in a process memory. """

import argparse
import logging
import os
import pickle
import sys
import time
import ctypes
import subprocess
import json

from haystack import model
from haystack import argparse_utils
from haystack.memory_mapper import MemoryMapper as MemoryMapper
from haystack import memory_mapping 

from haystack.utils import xrange

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log=logging.getLogger('haystack')

if not sys.platform.startswith('win'):
  environSep = ':'
else:
  environSep = ';'



class StructFinder:
  ''' Generic structure finder.
  Will search a structure defined by it's pointer and other constraints.
  Address space is defined by  mappings.
  Target memory perimeter is defined by targetMappings.
  targetMappings is included in mappings.
  
  @param mappings: address space
  @param targetMappings: search perimeter. If None, all mappings are used in the search perimeter.
  '''
  def __init__(self, mappings, targetMappings=None, updateCb=None):
    self.mappings = mappings
    if type(mappings) == bool:
      raise TypeError()
    self.targetMappings = targetMappings
    if targetMappings is None:
      self.targetMappings = mappings
    log.debug('StructFinder on %d memorymappings. Search Perimeter on %d mappings.'%(len(self.mappings), len(self.targetMappings)) )
    return
    
  def find_struct(self, structType, hintOffset=0, maxNum = 10, maxDepth=10 ):
    """ Iterate on all targetMappings to find a structure. """
    log.warning("Restricting search to %d memory mapping."%(len(self.targetMappings)))
    outputs=[]
    for m in self.targetMappings:
      ##debug, most structures are on head
      log.info("Looking at %s (%d bytes)"%(m, len(m)))
      #if not hasValidPermissions(m):
      #  log.warning("Invalid permission for memory %s. Stil looking at it"%m)
      #  #continue
      #else:
      #  log.debug("%s,%s"%(m,m.permissions))
      log.debug('look for %s'%(structType))
      outputs.extend(self.find_struct_in( m, structType, hintOffset=hintOffset, maxNum=maxNum, maxDepth=maxDepth))
      # check out
      if len(outputs) >= maxNum:
        log.debug('Found enough instance. returning results.')
        break
    # if we mmap, we could yield
    return outputs

  def find_struct_in(self, memoryMap, structType, hintOffset=0, maxNum=10, maxDepth=99 ):
    '''
      Looks for structType instances in memory, using :
        hints from structType (default values, and such)
        guessing validation with instance(structType)().isValid()
        and confirming with instance(structType)().loadMembers()
      
      returns POINTERS to structType instances.
    '''

    # update process mappings
    log.debug("scanning 0x%lx --> 0x%lx %s"%(memoryMap.start,memoryMap.end,memoryMap.pathname) )

    # where do we look  
    start=memoryMap.start  
    end=memoryMap.end
    plen=ctypes.sizeof(ctypes.c_void_p) # use aligned words only
    structlen=ctypes.sizeof(structType)
    #ret vals
    outputs=[]
    # alignement
    if hintOffset in memoryMap: # absolute offset
      align=hintOffset%plen
      start=hintOffset-align
    elif hintOffset != 0 and hintOffset  < end-start: # relative offset
      align=hintOffset%plen
      start=start+ (hintOffset-align)
     
    # parse for structType on each aligned word
    log.debug("checking 0x%lx-0x%lx by increment of %d"%(start, (end-structlen), plen))
    instance=None
    import time
    t0=time.time()
    p=0
    # xrange sucks. long int not ok
    for offset in xrange(start, end-structlen, plen):
      if offset % (1024<<6) == 0:
        p2=offset-start
        log.debug('processed %d bytes  - %02.02f test/sec'%(p2, (p2-p)/(plen*(time.time()-t0)) ))
        t0=time.time()
        p=p2
      instance,validated = self.loadAt( memoryMap, offset, structType, maxDepth) 
      if validated:
        log.debug( "found instance @ 0x%lx"%(offset) )
        # do stuff with it.
        outputs.append( (instance,offset) )
      if len(outputs) >= maxNum:
        log.debug('Found enough instance. returning results. find_struct_in')
        break
    return outputs


  def loadAt(self, memoryMap, offset, structType, depth=99 ):
    ''' 
      loads a haystack ctypes structure from a specific offset. 
        return (instance,validated) with instance being the haystack ctypes structure instance and validated a boolean True/False.
    '''
    log.debug("Loading %s from 0x%lx "%(structType,offset))
    instance=structType.from_buffer_copy(memoryMap.readStruct(offset,structType))
    # check if data matches
    if ( instance.loadMembers(self.mappings, depth) ):
      log.info( "found instance %s @ 0x%lx"%(structType,offset) )
      # do stuff with it.
      validated=True
    else:
      log.debug("Address not validated")
      validated=False
    return instance,validated


class VerboseStructFinder(StructFinder):
  ''' structure finder with a update callback to be more verbose.
  Will search a structure defined by it's pointer and other constraints.
  Address space is defined by  mappings.
  Target memory perimeter is defined by targetMappings.
  targetMappings is included in mappings.
  
  @param mappings: address space
  @param targetMappings: search perimeter. If None, all mappings are used in the search perimeter.
  @param updateCb: callback func. for periodic status update
  '''
  def __init__(self,mappings, targetMappings=None, updateCb=None):
    StructFinder.__init__(self,mappings, targetMappings)
    self.updateCb = updateCb
    self._updateCb_init()
    
  def _updateCb_init(self):
    # approximation
    nb = lambda x : ((x.end-x.start)/4)
    self._update_nb_steps = sum([nb(m) for m in self.targetMappings])
    self._update_i = 0

  def loadAt(self, memoryMap, offset, structType, depth=99 ):
    self._update_i+=1
    self.updateCb(self._update_i)
    StructFinder.loadAt(memoryMap, offset, structType, depth=depth )




def hasValidPermissions(memmap):
  ''' memmap must be 'rw..' or shared '...s' '''
  perms=memmap.permissions
  return (perms[0] == 'r' and perms[1] == 'w') or (perms[3] == 's')


def _callFinder(cmd_line):
  """ Call the haystack finder in a subprocess. Will use pickled objects to communicate results. """
  log.debug(cmd_line)
  env = os.environ
  env['PYTHONPATH'] = environSep.join(sys.path) # add possible pythonpaths to environnement
  p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, close_fds=True , env=env)
  p.wait()
  instance=p.stdout.read()
  instance=pickle.loads(instance)
  return instance

def getMainFile():
  return os.path.abspath(sys.modules[__name__].__file__)


def checkModulePath(typ):
  '''
    add typ module's path to sys.path
    If the type is a generated haystack structure type, 
    dump the '_generated' string from the module name and import it under the new module name.
  '''
  name = typ.__name__
  module,sep,kname = name.rpartition('.')
  # add the __file__ module to sys.path for it to be reachable by subprocess
  moddir = os.path.dirname(sys.modules[typ.__module__].__file__)
  if moddir not in sys.path:
    sys.path.append( moddir )
  # check if it's a generated module
  if typ.__module__.endswith('_generated'):
    # try to import the ctypes_name to get aliases up and running
    # otherwise, pyObj will not be created, and the module will not be registered in haystack model
    try:
      plainmod = typ.__module__.replace('_generated','')
      mod = __import__( plainmod, globals(), locals(), [kname])
      structName = '.'.join([plainmod , kname])
      log.info('trying %s instead of %s'%(structName, name))
      return structName
    except ImportError:
      # shhh  
      pass
  structName = '.'.join([typ.__module__,typ.__name__]) # we pass a str anyway...
  return structName

def _findStruct(pid=None, memfile=None, memdump=None, structType=None, maxNum=1, 
              fullScan=False, nommap=False, hint=None, debug=None, quiet=True ):
  ''' 
    Find all occurences of a specific structure from a process memory.
    Returns occurences as objects.

    Call a subprocess to ptrace a process. That way, self.process is not attached to the target PID by any means.
    
    @param pid is the process PID.
    @param memfile the file containing a direct dump of the memory mapping ( optionnal)
    @param memdump the file containing a memory dump 
    @param structType the structure type.
    @param offset the offset from which the structure must be loaded.
    @param debug if True, activate debug logs.
    @param maxNum the maximum number of expected results. Searching will stop after that many findings. -1 is unlimited.
  '''
  if type(structType) != type(ctypes.Structure):
    raise TypeError('structType arg must be a ctypes.Structure')
  structName = checkModulePath(structType) # add to sys.path
  cmd_line=[sys.executable, getMainFile(), "%s"%structName]
  if quiet:
    cmd_line.insert(2,"--quiet")
  elif debug:
    cmd_line.insert(2,"--debug")
  if nommap:
    cmd_line.insert(2,'--nommap')
  # three cases  
  if pid:       
    ### live PID. with mmap or not 
    cmd_line.extend(["--pid", "%d"%pid ])
  elif memfile: 
    ### proc mappings dump file
    cmd_line.extend([ "--memfile", memfile] )
  cmd_line.append('--pickled')
  # always add search
  cmd_line.extend(['search',  '--maxnum', str(int(maxNum))] )
  if fullScan:
    cmd_line.append('--fullscan')
  if hint:
    cmd_line.extend(['--hint', str(hex(hint))])
  # call me
  outs=_callFinder(cmd_line)
  if len(outs) == 0:
    log.error("The %s has not been found."%(structName))
    return None
  #
  return outs

def findStruct(pid, structType, maxNum=1, fullScan=False, nommap=False, debug=False, quiet=True):
  ''' 
    Find all occurences of a specific structure from a process memory.
    
    @param pid is the process PID.
    @param structType the structure type.
    @param maxNum the maximum number of expected results. Searching will stop after that many findings. -1 is unlimited.
    @param fullScan obselete
    @param nommap if True, do not use mmap while searching.
    @param debug if True, activate debug logs.
  '''
  return _findStruct(pid=pid, structType=structType, maxNum=maxNum, fullScan=fullScan, nommap=nommap, debug=debug, quiet=quiet)
  
def findStructInFile(filename, structType, hint=None, maxNum=1, fullScan=False, debug=False, quiet=True):
  ''' 
    Find all occurences of a specific structure from a process memory in a file.
    
    @param filename is the file containing the memory mapping content.
    @param structType the structure type.
    @param maxNum the maximum number of expected results. Searching will stop after that many findings. -1 is unlimited.
    @param hint obselete
    @param fullScan obselete
    @param debug if True, activate debug logs.
  '''
  return _findStruct(memfile=filename, structType=structType, maxNum=maxNum, fullScan=fullScan, debug=debug, quiet=quiet)


def refreshStruct(pid, structType, offset, debug=False, nommap=False):
  ''' 
    returns the pickled or text representation of a structure, from a given offset in a process memory.
    
    @param pid is the process PID.
    @param structType the structure Type.
    @param offset the offset from which the structure must be loaded.
    @param debug if True, activate debug logs.
    @param nommap if True, do not use mmap when mapping the memory
  '''
  if type(structType) != type(ctypes.Structure):
    raise TypeError('structType arg must be a ctypes.Structure')
  structName = checkModulePath(structType) # add to sys.path
  cmd_line=[sys.executable, getMainFile(),  '%s'%structName]
  if debug:
    cmd_line.insert(2,"--debug")
  if nommap:
    cmd_line.insert(2,'--nommap')
  # three cases  
  if pid:       
    ### live PID. with mmap or not 
    cmd_line.extend(["--pid", "%d"%pid ])
  elif memfile: 
    ### proc mappings dump file
    cmd_line.extend([ "--memfile", memfile] )
  cmd_line.append('--pickled')
  # always add search
  cmd_line.extend(['refresh',  "0x%lx"%offset] )
  instance,validated=_callFinder(cmd_line)
  if not validated:
    log.error("The session_state has not been re-validated. You should look for it again.")
    return None,None
  return instance,offset

def argparser():
  """
    Builds the argparse tree.
    See the command line --help .
  """
  rootparser = argparse.ArgumentParser(prog='StructFinder', description='Parse memory structs and pickle them.')
  rootparser.add_argument('--debug', dest='debug', action='store_const', const=True, help='setLevel to DEBUG')
  rootparser.add_argument('--quiet', dest='quiet', action='store_const', const=True, help='setLevel to ERROR only')
  rootparser.add_argument('--interactive', dest='interactive', action='store_const', const=True, help='drop to python command line after action')
  rootparser.add_argument('--nommap', dest='mmap', action='store_const', const=False, default=True, help='disable mmap()-ing')
  rootparser.add_argument('structName', type=str, help='Structure type name')
  rootparser.add_argument('--baseOffset', type=str, help='base offset of the memory map in the dump file.')
  
  target = rootparser.add_mutually_exclusive_group(required=True)
  target.add_argument('--pid', type=int, help='Target PID')
  target.add_argument('--memfile', type=argparse.FileType('r'), help='Use a file memory dump instead of a live process ID')
  target.add_argument('--dumpname', type=argparse_utils.readable, help='Use a haystack memory dump instead of a live process ID')

  output = rootparser.add_mutually_exclusive_group(required=True)
  output.add_argument('--string', dest='human', action='store_const', const=True, help='Print results as human readable string')
  output.add_argument('--json', dest='json', action='store_const', const=True, help='Print results as json readable string')
  output.add_argument('--pickled', dest='pickled', action='store_const', const=True, help='Print results as pickled string')
    
  subparsers = rootparser.add_subparsers(help='sub-command help')
  search_parser = subparsers.add_parser('search', help='search help')
  search_parser.add_argument('--fullscan', action='store_const', const=True, default=False, help='do a full memory scan, otherwise, restrict to the heap')
  search_parser.add_argument('--maxnum', type=int, action='store', default=1, help='Limit to maxnum numbers of results')
  search_parser.add_argument('--hint', type=int16, action='store', default=0, help='hintOffset to start at in hex')
  search_parser.set_defaults(func=search)
  #
  refresh_parser = subparsers.add_parser('refresh', help='refresh help')
  refresh_parser.add_argument('addr', type=str, help='Structure memory address')
  refresh_parser.set_defaults(func=refresh)
  #
  return rootparser

def int16( v):
  return int(v,16)

def getKlass(name):
  '''
    Returns the class type from a structure name.
    The class' module is dynamically loaded.
    
    @param name a haystack structure's text name. ( 'sslsnoop.ctypes_openssh.session_state' for example )
  '''
  module,sep,kname=name.rpartition('.')
  mod = __import__(module, globals(), locals(), [kname])
  klass = getattr(mod, kname)  

  log.debug('klass: %s'%(name))
  log.debug('module: %s'%(module))
  log.debug(getattr(mod, kname))
  #log.error(getattr(mod, kname+'_py'))
  return klass

def searchIn(structName, mappings, targetMappings=None, maxNum=-1):
  """
    Search a structure in a specific memory mapping.
    
    if targetMappings is not specified, the search will occur in each memory mappings
     in mappings.
    
    @param structName the structure name.
    @param mappings the memory mappings list.
    @param targetMappings the list of specific mapping to look into.
    @param maxNum the maximum number of results expected. -1 for infinite.
  """
  log.debug('searchIn: %s - %s'%(structName,mappings))
  structType = getKlass(structName)
  finder = StructFinder(mappings, targetMappings)
  # find all possible structType instance
  outs=finder.find_struct( structType, maxNum=maxNum)
  # prepare outputs
  ret=[ (ss.toPyObject(),addr) for ss, addr in outs]
  if len(ret) >0:
    log.debug("%s %s"%(ret[0], type(ret[0]) )   )
  if model.findCtypesInPyObj(ret):
    log.error('=========************======= CTYPES STILL IN pyOBJ !!!! ')
  return ret

def search(args):
  """
  Default function for the search command line option.
  Search a process's memory for a specific Structure.
  Returns findings in pickled or text format.
  
  See the command line --help .
  """
  log.debug('args: %s'%args)
  structType = getKlass(args.structName)
  if args.baseOffset:
    args.baseOffset=int(args.baseOffset,16)
  mappings = MemoryMapper(args).getMappings()
  if args.fullscan:
    targetMapping = mappings
  else:
    if args.hint:
      log.debug('Looking for the mmap containing the hint addr.')
      m = mappings.getMmapForAddr(args.hint)
      if not m:
        log.error('This hint is not a valid addr (0x%x)'%(args.hint))
        return
      targetMapping = [m]
    else:
      targetMapping = [m for m in mappings if m.pathname == '[heap]']
    targetMapping = memory_mapping.Mappings(targetMapping, mappings.name)
    if len(targetMapping) == 0:
      log.warning('No memorymapping found. Searching everywhere.')
      targetMapping = mappings
  finder = StructFinder(mappings, targetMapping)
  try:
    outs=finder.find_struct( structType, hintOffset=args.hint ,maxNum=args.maxnum)
  except KeyboardInterrupt,e:
    from meliae import scanner
    scanner.dump_all_objects('haystack-search.dump')
    if not args.debug:
      raise e
    import code
    code.interact(local=locals())
    return None
  #return
  ## debug
  if args.interactive:
    import code
    code.interact(local=locals())
  ##
  if args.human:
    print '[',
    for ss, addr in outs:
      print "# --------------- 0x%lx \n"% addr, ss.toString()
      pass
    print ']'
  else:
    ret=[ (ss.toPyObject(),addr) for ss, addr in outs]
    if len(ret) >0:
      log.debug("%s %s"%(ret[0], type(ret[0]) )   )
    if model.findCtypesInPyObj(ret):
      log.error('=========************======= CTYPES STILL IN pyOBJ !!!! ')
    if args.json: #jsoned
      print json.dumps(ret, default=model.json_encode_pyobj ) #cirular refs kills it check_circular=False, 
    else: #pickled
      print pickle.dumps(ret)
  return outs


def refresh(args):
  """
  Default function for the refresh command line option.
  Try to map a Structure from a specific offset in memory.
  Returns it in pickled or text format.
  
  See the command line --help .
  """
  log.debug(args)

  addr=int(args.addr,16)
  structType=getKlass(args.structName)

  mappings = MemoryMapper(args).getMappings()
  finder = StructFinder(mappings)
  
  memoryMap = model.is_valid_address_value(addr, finder.mappings)
  if not memoryMap:
    log.error("the address is not accessible in the memoryMap")
    raise ValueError("the address is not accessible in the memoryMap")
  instance,validated = finder.loadAt( memoryMap , 
          addr, structType)
  ##
  if args.interactive:
    import code
    code.interact(local=locals())
  if validated:
    if args.human:
       print '( %s, %s )'%(instance.toString(),validated)
    else:
      d=(instance.toPyObject(),validated)
      if model.findCtypesInPyObj(d[0]):
        log.error('=========************======= CTYPES STILL IN pyOBJ !!!! ')
      if args.json: #jsoned
        print json.dumps(ret)
      else: #pickled
        print pickle.dumps(d)
  else:
    if args.human:
      #Unloaded datastruct, printing safe __str__
      print '( %s, %s )'%(instance,validated)
    else:
      d=None
      if args.json: #jsoned
        print json.dumps(ret)
      else: #pickled
        print pickle.dumps(d)
  return instance,validated


def main(argv):
  
  parser = argparser()
  opts = parser.parse_args(argv)
  if opts.debug:
    logging.basicConfig(level=logging.DEBUG)
  elif opts.quiet:
    logging.basicConfig(level=logging.ERROR)    
  else:
    logging.basicConfig(level=logging.INFO)

  if opts.json:
    log.warning('the JSON feature is experimental and probably wont work.')
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Structure type does not exists.')
    log.error('sys.path is %s'%sys.path)
    print e

  if opts.pid:  
    log.debug("done for pid %d"%opts.pid)
  elif opts.memfile:
    log.debug("done for file %s"%opts.memfile.name)
  elif opts.dumpname:
    log.debug("done for file %s"%opts.dumpname)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


