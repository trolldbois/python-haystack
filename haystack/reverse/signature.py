#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tools around structure signature"""

import logging
import argparse
import sys
import re
import struct
import ctypes

from haystack import dump_loader
from haystack.utils import xrange
from haystack.reverse import pointerfinder

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Beta"


log = logging.getLogger('signature')


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
  

def _openDumpfile(dumpname):
  # load memorymapping
  mappings = dump_loader.load(dumpanme)
  # TODO : make a mapping chooser 
  if len(mappings) > 1:
    heap = [m for m in mappings if m.pathname == '[heap]'][0]
  else:
    heap = mappings[0]
  return heap

def toFile(dumpname, outputFile):
  log.info('Loading the mappings in the memory dump file.')
  mapping = _openDumpfile(dumpname)
  log.info('Make the signature.')
  sigMaker = SignatureMaker(mapping)
  sig = sigMaker.search()
  outputFile.write(sig)
  log.info('Signature written to %s.'%(outputFile.name))
  del sig
  del sigMaker
  return

def makesig(opt):
  toFile(opt.dumpname, opt.sigfile)
  pass
  
def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-sig', description='Make a heap signature.')
  rootparser.add_argument('dumpname', type=argparse_utils.readable, action='store', help='Source memory dump by haystack.')
  rootparser.add_argument('sigfile', type=argparse.FileType('wb'), action='store', help='The output signature filename.')
  rootparser.set_defaults(func=makesig)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('ctypes_openssh').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('gui').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
