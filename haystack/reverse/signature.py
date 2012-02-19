#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tools around structure signature"""

import logging
import argparse
import os
import sys
import re
import Levenshtein #seqmatcher ?
import networkx


import haystack
import haystack.model
from haystack import dump_loader
from haystack import argparse_utils
from haystack.config import Config
from haystack.utils import xrange
from haystack.reverse import pointerfinder
from haystack.reverse import utils
from haystack.reverse.reversers import *

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Beta"


log = logging.getLogger('signature')


class SignatureGroupMaker:
  """From a list of addresses, groups similar signature together.
  HINT: structure should be resolved but not reverse-patternised for arrays...??"""
  def __init__(self, context, name, addrs):
    self._name = name
    self._structures_addresses = addrs
    self._context = context
  
  def _init_signatures(self):
    # get text signature for Counter to parse
    # need to force resolve of structures
    self._signatures = []
    for addr in self._structures_addresses:
      self._context.getStructureForAddr(addr).decodeFields() # can be long
      self._signatures.append( (addr, self._context.getStructureForAddr(addr).getSignature(True)) )
    return
    
  def make(self):
    self._init_signatures()
    #
    self._similarities = []
    for i,x1 in enumerate(self._signatures[:-1]):
      for x2 in self._signatures[i+1:]:
        addr1, el1 = x1
        addr2, el2 = x2
        lev=Levenshtein.ratio(el1,el2) # seqmatcher ?
        if lev >0.75:
          #self._similarities.append( ((addr1,el1),(addr2,el2)) )
          self._similarities.append( (addr1,addr2) )
          # we do not need the signature.
    # check for chains
    # TODO      we need a group maker with an iterator to push group proposition to the user
    log.debug('\t[-] Signatures done.')
    return

  def persist(self):
    outdir = Config.getCacheFilename(Config.CACHE_SIGNATURE_GROUPS_DIR, self._context.dumpname)
    if not os.path.isdir(outdir):
      os.mkdir(outdir)
    if not os.access(outdir, os.W_OK):
      raise IOError('cant write to %s'%(outdir))
    #
    outname = os.path.sep.join([outdir,self._name])
    ar = utils.int_array_save(outname, self._similarities)
    return
    
  def isPersisted(self):
    outdir = Config.getCacheFilename(Config.CACHE_SIGNATURE_GROUPS_DIR, self._context.dumpname)
    return os.access(os.path.sep.join([outdir,self._name]), os.F_OK)

  def load(self):
    outdir = Config.getCacheFilename(Config.CACHE_SIGNATURE_GROUPS_DIR, self._context.dumpname)
    inname = os.path.sep.join([outdir,self._name])
    self._similarities = utils.int_array_cache(inname)
    return 

  def getGroups(self):
    return self._similarities    

class StructureSizeCache:
  """Loads structures, get their signature (and size) and sort them in 
  fast files dictionaries."""
  def __init__(self,ctx):
    self._context = ctx
    self._sizes = None
  
  def _loadCache(self):
    outdir = Config.getCacheFilename(Config.CACHE_SIGNATURE_SIZES_DIR, self._context.dumpname)
    fdone = os.path.sep.join([outdir, Config.CACHE_SIGNATURE_SIZES_DIR_TAG]) 
    if not os.access(fdone, os.R_OK):
      return False
    for myfile in os.listdir(outdir):
      try:
        addr = int( myfile.split(_)[1], 16 )
      except IndexError,e:
        continue # ignore file
    
      
  def cacheSizes(self):
    """Find the number of different sizes, and creates that much numpyarray"""
    # if not os.access
    outdir = Config.getCacheFilename(Config.CACHE_SIGNATURE_SIZES_DIR, self._context.dumpname)
    if not os.path.isdir(outdir):
      os.mkdir(outdir)
    if not os.access(outdir, os.W_OK):
      raise IOError('cant write to %s'%(outdir))
    #
    sizes = set(self._context._malloc_sizes)
    arrays = dict([(s,[]) for s in sizes])
    #sort all addr in all sizes.. 
    [arrays[ self._context._malloc_sizes[i] ].append(addr) for i, addr in enumerate(self._context._malloc_addresses) ]
    #saving all sizes dictionary in files...
    for size,lst in arrays.items():
      fout = os.path.sep.join([outdir, 'size.%0.4x'%(size)])
      arrays[size] = utils.int_array_save( fout , lst) 
    #saved all sizes dictionaries.
    # tag it as done
    file(os.path.sep.join([outdir, Config.CACHE_SIGNATURE_SIZES_DIR_TAG]),'w')
    self._sizes = arrays    
    return
    
  def getStructuresOfSize(self, size):
    if self._sizes is None:
      self.cacheSizes()
    if size not in self._sizes:
      return []
    return numpy.asarray(self._sizes[size])
    
  def __iter__(self):
    if self._sizes is None:
      self.cacheSizes()
    for size in self._sizes.keys():
      yield (size, numpy.asarray(self._sizes[size]) )
  
      
class SignatureMaker(pointerfinder.AbstractSearcher):
  ''' 
  make a condensed signature of the mapping. 
  We could then search the signature file for a specific signature
  '''
  
  NULL = 0x1
  POINTER = 0x2 
  #POINTERS = NULL | POINTER # null can be a pointer value so we can byte-test that
  OTHER = 0x4

  def __init__(self, mapping):
    pointerfinder.AbstractSearcher.__init__(self,mapping)
    self.pSearch = pointerfinder.PointerSearcher(self.getSearchMapping()) 
    self.nSearch = pointerfinder.NullSearcher(self.getSearchMapping()) 
    
  def testMatch(self, vaddr):
    ''' return either NULL, POINTER or OTHER '''
    if self.nSearch.testMatch(vaddr):
      return self.NULL
    if self.pSearch.testMatch(vaddr):
      return self.POINTER
    return self.OTHER

  def search(self):
    ''' returns the memspace signature. Dont forget to del that object, it's big. '''
    self.values = b''
    log.debug('search %s mapping for matching values'%(self.getSearchMapping()))
    for vaddr in xrange(self.getSearchMapping().start, self.getSearchMapping().end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      self.values += struct.pack('B', self.testMatch(vaddr))
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to return the signature of that memspace '''
    log.debug('iterate %s mapping for matching values'%(self.getSearchMapping()))
    for vaddr in xrange(self.getSearchMapping().start, self.getSearchMapping().end, self.WORDSIZE):
      self._checkSteps(vaddr) # be verbose
      yield struct.pack('B',self.testMatch(vaddr))
    return 


class PointerSignatureMaker(SignatureMaker):
  def testMatch(self, vaddr):
    ''' return either POINTER or OTHER '''
    if self.pSearch.testMatch(vaddr):
      return self.POINTER
    return self.OTHER




class RegexpSearcher(pointerfinder.AbstractSearcher):
  ''' 
  Search by regular expression in memspace.
  '''
  def __init__(self, mapping, regexp):
    pointerfinder.AbstractSearcher.__init__(self,mapping)
    self.regexp = regexp
    self.pattern = re.compile(regexp, re.IGNORECASE)

  def search(self):
    ''' find all valid matches offsets in the memory space '''
    self.values = set()
    log.debug('search %s mapping for matching values %s'%(self.getSearchMapping(), self.regexp))
    for match in self.getSearchMapping().finditer(self.getSearchMapping().mmap().getByteBuffer()):
      offset = match.start()
      if type(value) == list :
        value = ''.join([chr(x) for x in match.group()])
      vaddr = offset+self.getSearchMapping().start
      self._checkSteps(vaddr) # be verbose
      self.values.add((vaddr,value) )
    return self.values    
    
  def __iter__(self):
    ''' Iterate over the mapping to find all valid matches '''
    log.debug('iterate %s mapping for matching values'%(self.getSearchMapping()))
    for match in self.pattern.finditer(self.getSearchMapping().mmap().getByteBuffer()):
      offset = match.start()
      value = match.group(0) # [] of int ?
      if type(value) == list :
        value = ''.join([chr(x) for x in match.group()])
      vaddr = offset+self.getSearchMapping().start
      self._checkSteps(vaddr) # be verbose
      yield (vaddr,value) 
    return 

  def testMatch(self, vaddr):
    return True

#EmailRegexp = r'''[a-zA-Z0-9+_\-\.]+@[0-9a-zA-Z][.-0-9a-zA-Z]*.[a-zA-Z]+'''
EmailRegexp = r'''((\"[^\"\f\n\r\t\v\b]+\")|([\w\!\#\$\%\&\'\*\+\-\~\/\^\`\|\{\}]+(\.[\w\!\#\$\%\&\'\*\+\-\~\/\^\`\|\{\}]+)*))@((\[(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))\])|(((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|([0-1]?[0-9]?[0-9])))|((([A-Za-z0-9\-])+\.)+[A-Za-z\-]+))'''
URLRegexp = r'''[a-zA-Z0-9]+://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'''
#URIRegexp = r'''#^([a-z0-9+\-.]+):([/]{0,2}([a-z0-9\-._~%!\$&'\(\)\*+,;=:]+@)?([\[\]a-z0-9\-._~%!\$&'\(\)\*+,;=:]+(:[0-9]+)?))([a-z0-9\-._~%!\$&'\(\)\*+,;=:@/]*)(\?[\?/a-z0-9\-._~%!\$&'\(\)\*+,;=:@]+)?(\#[a-z0-9\-._~%!\$&'\(\)\*+,;=:@/\?]+)?#i'''
WinFileRegexp = r'''([a-zA-Z]\:)(\\[^\\/:*?<>"|]*(?<![ ]))*(\.[a-zA-Z]{2,6})'''
#WinFileRegexp = r'''(.*?)([^/\\]*?)(\.[^/\\.]*)?'''
IPv4Regexp = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'''
IPv6Regexp = r'''(::|(([a-fA-F0-9]{1,4}):){7}(([a-fA-F0-9]{1,4}))|(:(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){1,6}:)|((([a-fA-F0-9]{1,4}):)(:([a-fA-F0-9]{1,4})){1,6})|((([a-fA-F0-9]{1,4}):){2}(:([a-fA-F0-9]{1,4})){1,5})|((([a-fA-F0-9]{1,4}):){3}(:([a-fA-F0-9]{1,4})){1,4})|((([a-fA-F0-9]{1,4}):){4}(:([a-fA-F0-9]{1,4})){1,3})|((([a-fA-F0-9]{1,4}):){5}(:([a-fA-F0-9]{1,4})){1,2}))'''
SQLRegexp = r'''(SELECT\s[\w\*\)\(\,\s]+\sFROM\s[\w]+)| (UPDATE\s[\w]+\sSET\s[\w\,\'\=]+)| (INSERT\sINTO\s[\d\w]+[\s\w\d\)\(\,]*\sVALUES\s\([\d\w\'\,\)]+)| (DELETE\sFROM\s[\d\w\'\=]+)'''
CCardRegexp = r'''((4\d{3})|(5[1-5]\d{2}))(-?|\040?)(\d{4}(-?|\040?)){3}|^(3[4,7]\d{2})(-?|\040?)\d{6}(-?|\040?)\d{5}'''
SSNRegexp = r'''\d{3}-\d{2}-\d{4}'''
GUIDRegexp = r'''([A-Fa-f0-9]{32}| [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}| \{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\})'''
#UNCRegexp = r'''((\\\\[a-zA-Z0-9-]+\\[a-zA-Z0-9`~!@#$%^&(){}'._-]+([ ]+[a-zA-Z0-9`~!@#$%^&(){}'._-]+)*)|([a-zA-Z]:))(\\[^ \\/:*?""<>|]+([ ]+[^ \\/:*?""<>|]+)*)*\\?'''
#UNCRegexp = r'(([a-zA-Z]:|\\)\\)?(((\.)|(\.\.)|([^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?))\\)*[^\\/:\*\?"\|<>\. ](([^\\/:\*\?"\|<>\. ])|([^\\/:\*\?"\|<>]*[^\\/:\*\?"\|<>\. ]))?'


def looksLikeUTF8(bytearray):
  p = re.compile("\\A(\n" +
    r"  [\\x09\\x0A\\x0D\\x20-\\x7E]             # ASCII\\n" +
    r"| [\\xC2-\\xDF][\\x80-\\xBF]               # non-overlong 2-byte\n" +
    r"|  \\xE0[\\xA0-\\xBF][\\x80-\\xBF]         # excluding overlongs\n" +
    r"| [\\xE1-\\xEC\\xEE\\xEF][\\x80-\\xBF]{2}  # straight 3-byte\n" +
    r"|  \\xED[\\x80-\\x9F][\\x80-\\xBF]         # excluding surrogates\n" +
    r"|  \\xF0[\\x90-\\xBF][\\x80-\\xBF]{2}      # planes 1-3\n" +
    r"| [\\xF1-\\xF3][\\x80-\\xBF]{3}            # planes 4-15\n" +
    r"|  \\xF4[\\x80-\\x8F][\\x80-\\xBF]{2}      # plane 16\n" +
    r")*\\z", re.VERBOSE)

  phonyString = bytearray.encode("ISO-8859-1")
  return p.matcher(phonyString).matches()

'''
lib["email"] = re.compile(r"(?:^|\s)[-a-z0-9_.]+@(?:[-a-z0-9]+\.)+[a-z]{2,6}(?:\s|$)",re.IGNORECASE)
lib["postcode"] = re.compile("[a-z]{1,2}\d{1,2}[a-z]?\s*\d[a-z]{2}",re.IGNORECASE)
lib["zipcode"] = re.compile("\d{5}(?:[-\s]\d{4})?")
lib["ukdate"] = re.compile \
("[0123]?\d[-/\s\.](?:[01]\d|[a-z]{3,})[-/\s\.](?:\d{2})?\d{2}",re.IGNORECASE)
lib["time"] = re.compile("\d{1,2}:\d{1,2}(?:\s*[aApP]\.?[mM]\.?)?")
lib["fullurl"] = re.compile("https?://[-a-z0-9\.]{4,}(?::\d+)?/[^#?]+(?:#\S+)?",re.IGNORECASE)
lib["visacard"] = re.compile("4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["mastercard"] = re.compile("5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}")
lib["phone"] = re.compile("0[-\d\s]{10,}")
lib["ninumber"] = re.compile("[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-z]",re.IGNORECASE)
lib["isbn"] = re.compile("(?:[\d]-?){9}[\dxX]")
  '''

def makeSizeCaches(dumpname):
  ''' gets all structures instances from the dump, order them by size.'''
  from haystack.reverse import reversers
  log.debug('\t[-] Loading the context for a dumpname.')
  context = reversers.getContext(dumpname)
  log.debug('\t[-] Make the size dictionnaries.')
  sizeCache = StructureSizeCache(context)
  sizeCache.cacheSizes()

  return context, sizeCache  
  
def buildStructureGroup(context, sizeCache , optsize=None ):
  ''' Iterate of structure instances grouped by size, find similar signatures, 
  and outputs a list of groups of similar structures instances.'''
  log.info("\t[-] Group structures's signatures by sizes.")
  sgms=[]
  #
  for size,lst in sizeCache:
    if optsize is not None:
      if size != optsize:
        continue # ignore different size
    log.debug("\t[-] Group signatures for structures of size %d"%(size))
    sgm = SignatureGroupMaker(context, 'structs.%x'%(size), lst )
    if sgm.isPersisted():
      sgm.load()
    else:
      sgm.make()
      sgm.persist()
    sgms.append(sgm)
    
    ## TODO DEBUG
    if len(lst) >100:
      log.error('too big a list, DELETE THIS ')
      continue
      #return
    
    # make a chain and use --originAddr
    log.info('\t[-] Sort %d structs of size %d in groups'%(len(lst), size))
    graph = networkx.Graph() 
    graph.add_edges_from(sgm.getGroups()) # add similarities as linked structs
    graph.add_nodes_from(lst) # add all structs all nodes . Should spwan isolated graphs
    subgraphs = networkx.algorithms.components.connected.connected_component_subgraphs(graph)
    #print 'subgraphs', len(subgraphs)
    chains = [g.nodes() for g in subgraphs ]
    # TODO, do not forget this does only gives out structs with similarities.
    # lonely structs are not printed here...
    
    yield chains
    
def printStructureGroups(context, chains, originAddr=None):      
  chains.sort()
  for chain in chains:
    log.debug('\t[-] chain len:%d'%len(chain) )
    if originAddr is not None:
      if originAddr not in chain:
        continue # ignore chain if originAddr is not in it
    for addr in chain:
      context.getStructureForAddr(addr).decodeFields() # can be long
      print context.getStructureForAddr(addr).toString()
    print '-'*80
  
  # TODO next next step, compare struct links in a DiGraph with node == struct size + pointer index as a field.


def makeReversedTypes(context, sizeCache):
  ''' Compare signatures for each size groups.
  Makes a chains out of similar structures. Changes the structure names for a single
  typename when possible. Changes the ctypes types of each pointer field.'''
  
  log.info('[+] Build groups of similar instances, create a reversed type for each group.')
  for chains in buildStructureGroup(context, sizeCache):
    fixType(context, chains)
  
  log.info('[+] For each instances, fix pointers fields to newly created types.')
  import ctypes
  for s in context.listStructures():
    s.reset()
    s.decodeFields()
    for f in s.getPointerFields():
      addr = f._getValue(0)
      if addr in context.heap:
        f.setCtype( ctypes.POINTER(context.getStructureForOffset(addr).getCtype()) )
        f.setComment('pointer fixed')
  
  log.info('[+] For new reversed type, fix their definitive fields.')
  for revStructType in context.listReversedTypes():
    revStructType.makeFields(context)
    
  return context
  
def makeSignatures(dumpname):
  from haystack.reverse import reversers
  log.debug('\t[-] Loading the context for a dumpname.')
  context = reversers.getContext(dumpname)
  heap = context.heap
  
  log.info('[+] Make the signatures.')
  sigMaker = SignatureMaker(heap)
  sig = sigMaker.search()
  return context, sig  

def makeGroupSignature(context, sizeCache): 
  ''' From the structures cache ordered by size, group similar instances together. '''
  log.info("[+] Group structures's signatures by sizes.")
  sgms=[]
  try:
    for size,lst in sizeCache:
      log.debug("[+] Group signatures for structures of size %d"%(size))
      sgm = SignatureGroupMaker(context, 'structs.%x'%(size), lst )
      sgm.make()
      sgm.persist()
      sgms.append(sgm)
  except KeyboardInterrupt,e:
    pass
  return context, sgms

# FIXME: 100 maybe is a bit short
try:
  import pkgutil
  _words = pkgutil.get_data(__name__, Config.WORDS_FOR_REVERSE_TYPES_FILE)
except ImportError:
  import pkg_resources
  _words = pkg_resources.resource_string(__name__, Config.WORDS_FOR_REVERSE_TYPES_FILE)
_NAMES = [ s.strip() for s in _words.split('\n') ]

def getname():
  global _NAMES
  if len(_NAMES) == 0:
    _NAMES = [ '%s%s'%(s1.strip(), s2.strip()) for s1 in _words.split('\n') for s2 in _words.split('\n') ]
  return _NAMES.pop()  
  

def fixType(context, chains):      
  ''' Fix the name of each structure to a generic word/type name '''
  for chain in chains:
    name = getname()
    log.debug('\t[-] fix type of size:%d with name name:%s'% (len(chain), name ) )
    for addr in chain:
      # FIXME 
      instance = context.getStructureForAddr(addr)
      #
      instance.setName(name)
      ctypes_type = context.getReversedType(name)
      if ctypes_type is None: # make type
        ctypes_type = structure.ReversedType.create( context, name )
      ctypes_type.addInstance( instance )
      context.getStructureForAddr(addr).setCtype(ctypes_type)
  return 



if __name__ == '__main__':
  pass
