#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
This module holds some basic utils function.
'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os
import encodings
import logging
import string

log = logging.getLogger('re_string')

_py_encodings = set(encodings.aliases.aliases.values())
#  except IOError: # TODO delete bz2 and gzip
#  except TypeError: # TODO delete hex_codec
#  except ValueError: # TODO delete uu_encode
_py_encodings.remove('mbcs')
_py_encodings.remove('hex_codec')
_py_encodings.remove('uu_codec')
_py_encodings.remove('bz2_codec')
_py_encodings.remove('zlib_codec')
_py_encodings.remove('base64_codec')
_py_encodings.remove('tactis')
_py_encodings.remove('rot_13')
_py_encodings.remove('quopri_codec')

# perf test, string.printable is limited to ascii anyway
# ...
_py_encodings = set(['ascii', 'latin_1','iso8859_15','utf_8','utf_16le','utf_32le',])


def try_decode_string(bytesarray, longerThan=1):
  ''' try to read string. Null terminated or not'''
  i = bytesarray.find('\x00')
  if i == -1:
    # find longuest readable
    for i,c in enumerate(bytesarray):
          if c not in string.printable:
            break
    if i < longerThan:
      return False
    readable = bytesarray[:i+1]
    ustrings = testAllEncodings(bytesarray[:i+1])
  else:
    ustrings = testAllEncodings(bytesarray)
  #all cases
  ustrings = [ (l,enc,ustr) for l,enc,ustr in ustrings if l > longerThan]
  if len(ustrings) == 0 : # 
    return False
  else: # len(ustrings) > 5 : # probably an ascii string 
    valid_strings = []
    i=0
    for size, codec, chars in ustrings :
      log.debug('%s %s'%(codec, repr(chars)) )
      # check not printable chars ( us ascii... )
      skip = False
      for i,c in enumerate(chars):
        if (i == (len(chars)-1)) and (chars[-1] =='\x00'): # last , NULL terminated
          break
        if c not in string.printable:
          skip = True
          if i < longerThan:
            log.debug('Too short/Not a string, %d/%d non printable characters "%s..."'%( len(notPrintable), i, chars[:25] ))
            break
          #else: valid string
          log.debug('shorten at %d - %s'%(i, chars[:i+1]))
          valid_strings.append( (i+1, codec, chars[:i+1] ) )
          break
      if skip:
        continue
      #else
      log.debug('valid entry %s'%(chars))
      valid_strings.append( (size, codec, chars) )
    if len(valid_strings) > 0:
      valid_strings.sort(reverse=True)
      return valid_strings[0]
    return False


def startsWithNulTerminatedString(bytesarray, longerThan=1):
  ''' if there is no \x00 termination, its not a string
  that means that if we have a bad pointer in the middle of a string, 
  the first part will not be understood as a string'''
  i = bytesarray.find('\x00')
  if i == -1:
    return False
  else:
    ustrings = testAllEncodings(bytesarray)
    ustrings = [ (l,enc,ustr) for l,enc,ustr in ustrings if l > longerThan]
    if len(ustrings) == 0 : # 
      return False
    else: # len(ustrings) > 5 : # probably an ascii string 
      notPrintableBool = True
      ustring = [[]]
      i=0
      for ustring in ustrings :
        #ustring = [(l,enc,s) for l,enc,s in ustrings if enc == 'ascii' ]
        # test ascii repr
        #if len(ustring) != 1:
        #  asciis = ustrings # only printable chars even in utf
        size = ustring[0]
        codec = ustring[1]
        chars = ustring[2]
        log.debug('%s %s'%(codec,repr(chars)) )
        # check not printable
        notPrintable = []
        for i,c in enumerate(chars):
          if c not in string.printable:
            notPrintable.append( (i,c) )
        if (len(notPrintable)/float(len(chars)) ) > 0.5:
          log.debug('Not a string, %d/%d non printable characters "%s..."'%( len(notPrintable), i, chars[:25] ))
          continue
        else:
          return ustring
      return False

#AnonymousStruct_48_182351808_1:
def testAllEncodings(bytesarray):
  res = []
  for codec in _py_encodings:
    length, my_str = testEncoding(bytesarray, codec)
    if length != -1:
      res.append( (length, codec, my_str) )
  res.sort(reverse=True)
  log.debug('%d valid decodes: \n%s'%(len(res), str(res)))
  return res
  
def testUTF8(bytesarray):
  return testEncoding(bytesarray, 'UTF-8')
def testUTF16(bytesarray):
  return testEncoding(bytesarray, 'UTF-16le')
def testUTF32(bytesarray):
  return testEncoding(bytesarray, 'UTF-32le')

def testEncoding(bytesarray, encoding):
  ''' test for null bytes on even bytes
  this works only for western txt in utf-16
  '''
  sizemultiplier = len('\x20'.encode(encoding))
  #log.debug('size: %d encoding: %s'%(sizemultiplier, encoding))
  try:
    ustr = bytesarray.decode(encoding)
  except UnicodeDecodeError:
    log.debug('UnicodeDecodeError: %s did not decode that'%(encoding))
    return -1, None
  except Exception, e:
    log.error('Error using encoding %s'%(encoding))
    raise e
  i = ustr.find('\x00')
  if i == -1:
    log.debug('%s was ok - but no NULL'%(encoding))
    end = len(ustr)
    #return -1, None
  else:
    # include NULL 
    end = i+1

  slen = sizemultiplier*end
  log.debug('%s is ok - with len %d'%(encoding, slen))
  return (slen, ustr[:end] )
    

  





















