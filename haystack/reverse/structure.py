#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import os
import pickle
import itertools
import numbers

from haystack.config import Config
import field
import utils

log = logging.getLogger('structure')

DEBUG_ADDRS=[]


# a 12 Mo heap takes 30 minutes on my slow notebook
# what is \xb2 padding for ?
# huge bug with zerroes fields aggregation
# the empty space at the end of the heap is making the reverse quite slow.... logs outputs line rate 10/sec againt 2k/sec

# TODO look for VFT and malloc metadata ?
# se stdc++ to unmangle c++
# vivisect ?
# TODO 1: make an interactive thread on that anon_struct and a struct Comparator to find similar struct.
#         that is a first step towards structure identification && naming. + caching of info
#      2: dump ctypes structure into python file + cache (vaddr, Structurectypes ) to pickle file ( reloading/continue possible with less recalculation )
# create a typename for \xff * 8/16. buffer color ? array of char?

# Compare sruct type from parent with multiple pointer (

class AnonymousStructInstance:
  '''
  AnonymousStruct in absolute address space.
  Comparaison between struct is done is relative addresse space.
  '''
  def __init__(self, mappings, vaddr, bytes, prefix=None):
    self.mappings = mappings
    self.vaddr = vaddr
    self.bytes = bytes
    self.fields = []
    if prefix is None:
      self.prefixname = '%lx'%(self.vaddr)
    else:
      self.prefixname = '%lx_%s'%( self.vaddr, self.prefix)
    self.resolved = False
    self.pointerResolved = False
    return
  
  def guessField(self, vaddr, typename=None, size=-1, padding=False ):
    offset = vaddr - self.vaddr
    if offset < 0 or offset > len(self):
      raise IndexError()
    if typename is None:
      typename = FieldType.UNKNOWN
    ## find the maximum size
    if size == -1:
      try: 
        nextStruct = itertools.dropwhile(lambda x: (x.offset < offset), sorted(self.fields) ).next()
        nextStructOffset = nextStruct.offset
      except StopIteration, e:
        nextStructOffset = len(self)
      maxFieldSize = nextStructOffset - offset
      size = maxFieldSize
    ##
    field = field.Field(self, offset, typename, size, padding)
    if typename == FieldType.UNKNOWN:
      if not field.decodeType():
        return None
    elif not field.check():
      return None
    if field.size == -1:
      raise ValueError('error here %s %s'%(field, field.typename))
    # field has been typed
    self.fields.append(field)
    self.fields.sort()
    return field

  def addField(self, vaddr, typename, size, padding ):
    offset = vaddr - self.vaddr
    return self._addField(offset, typename, size, padding)
    
  def _addField(self, offset, typename, size, padding):
    if offset < 0 or offset > len(self):
      raise IndexError()
    if typename is None:
      raise ValueError()
    # make a field with no autodecode
    field = field.Field(self, offset, typename, size, padding)
    # field has been typed
    self.fields.append(field)
    self.fields.sort()
    return field

  def save(self):
    self.fname = os.path.sep.join([Config.structsCacheDir, str(self)])
    pickle.dump(self, file(self.fname,'w'))
    return
  
  def _check(self,field):
    # TODO check against other fields
    return field.check()

  def decodeFields(self):
    ''' list all gaps between known fields 
        try to decode their type
            if no  pass, do not populate
            if yes add a new field
        compare the size of the gap and the size of the fiel
    '''
    # should be done by 
    #if len(self.fields) == 0: ## add a fake all-struct field
    #  self._addField(0, FieldType.UNKNOWN, size, True)
    self._fixGaps() # add padding zones
    gaps = [ f for f in self.fields if f.padding == True ] 
    sg = len(gaps)
    while  sg > 0 :
      log.debug('decode: %d gaps left'%(sg))
      # try to decode padding zone
      for field in self.fields:
        if field.decoded: # do not redecode, save
          continue
        #
        fieldType = field.decodeType()
        if fieldType is None: # we could not decode. mark it as unknown
          field.padding = False
          field.decoded = True
          continue
        # Found a new field in a padding, with a probable type...
        pass
      # reroll until completion
      self._fixGaps() 
      gaps = [ f for f in self.fields if f.padding == True ] 
      sg = len(gaps)
    #endwhile
    #aggregate zeroes fields
    self._aggregateZeroes()
    return

  def _aggregateZeroes(self):
    ''' sometimes we have a pointer in the middle of a zeroes buffer. we need to aggregate '''
    log.debug('aggregateZeroes: start')
    myfields = sorted([ f for f in self.fields if f.padding != True ])
    if len(myfields) < 2:
      log.debug('aggregateZeroes: not so much fields')
      return
    newFields = []
    newFields.append(myfields[0])
    for f in myfields[1:]:
      last = newFields[-1]
      if last.isZeroes() and f.isZeroes():
        log.debug('aggregateZeroes: field %s and %s -> %d:%d'%(last,f, last.offset,f.offset+len(f)))
        newFields[-1] = field.Field(self, last.offset, last.typename, len(last)+len(f), False)
      else:
        newFields.append(f)
    self.fields = newFields
    self._fixGaps()
    return
    
  def _fixGaps(self):
    ''' Fix this structure and populate empty offsets with default unknown padding fields '''
    nextoffset = 0
    self._gaps = 0
    overlaps = False
    self.fields = [ f for f in self.fields if f.padding != True ] # clean paddings to check new fields
    myfields = sorted(self.fields)
    for f in myfields:
      if f.offset > nextoffset : # add temp padding field
        self._gaps += 1
        padding = self._addField( nextoffset, FieldType.UNKNOWN, f.offset-nextoffset, True)
        log.debug('fixGaps: adding field at offset %d:%d'%(padding.offset, padding.offset+len(padding) ))
      elif f.offset < nextoffset :
        log.warning('fixGaps: overlapping fields at offset %d'%(f.offset))
        overlaps = True
      else: # == 
        pass
      nextoffset = f.offset + len(f)
    # conclude on QUEUE insertion
    if nextoffset < len(self):
      self._gaps += 1
      padding = self._addField( nextoffset, FieldType.UNKNOWN, len(self)-nextoffset, True)
      log.debug('fixGaps: adding field at queue offset %d:%d'%(padding.offset, padding.offset+len(padding) ))
    if self._gaps == 0:
      self.resolved = True
    if overlaps:
      log.debug('fixGaps: overlapping fields to fix')
      self._fixOverlaps()
    self.fields.sort()
    return
  

  def _fixOverlaps(self):
    ''' fix overlapping string fields '''
    fields = sorted([ f for f in self.fields if f.padding != True ]) # clean paddings to check new fields
    for f1, f2 in self._getOverlapping():
      log.debug('overlappings %s %s'%(f1,f2))
      f1_end = f1.offset+len(f1)
      f2_end = f2.offset+len(f2)
      if (f1.typename == f2.typename and
          f2_end == f1_end ): # same end, same type
        self.fields.remove(f2) # use the last one
        log.debug('Cleaned a  field overlaps %s %s'%(f1, f2))
      elif f1.isZeroes() and f2.isZeroes(): # aggregate
        log.debug('aggregate Zeroes')
        start = min(f1.offset,f2.offset)
        size = max(f1_end, f2_end)-start
        try:
          self.fields.remove(f1)
          self.fields.remove(f2)
          self.fields.append( field.Field(self, start, FieldType.ZEROES, size, False) )
        except ValueError,e:
          log.error('please bugfix')
      else: # TODO
        pass
    return
  
  def _getOverlapping(self):
    fields = sorted([ f for f in self.fields if f.padding != True ]) # clean paddings to check new fields
    lastend = 0
    oldf = None
    for f in fields:
      newend = f.offset + len(f)
      if f.offset < lastend:  ## overlaps
        yield ( oldf, f )
      oldf = f
      lastend = newend
    return
  
  def resolvePointers(self, structs_addrs, structCache):
    if self.pointerResolved:
      return
    resolved = 0
    pointerFields = self.getPointerFields()
    for field in pointerFields:
      # shorcut
      if hasattr(field, '_ptr_resolved'):
        if field._ptr_resolved:
          resolved+=1
          continue
      # if pointed is not None:  # erase previous info
      tgt = None
      if field.value in structs_addrs: 
        tgt = structCache[field.value]
        field._target_field = tgt[0]
      elif field.value in self.mappings.getHeap():
        # elif target is a STRING in the HEAP
        # set pointer type to char_p
        tgt_field = self._resolvePointerToStructField(field, structs_addrs, structCache)
        if tgt_field is not None:
          field.typename = FieldType.makePOINTER(tgt_field.typename)
          field._target_field = tgt_field
          tgt = '%s_field_%s'%(tgt_field.struct, tgt_field.getName())
        pass
      elif field.value in self.mappings: # other mappings
        tgt = 'ext_lib'
        field._ptr_to_ext_lib = True
        pass
      if tgt is not None:
        resolved+=1
        field.setName('%s_%s'%(field.typename.basename, tgt))
        field._ptr_resolved = True
    #
    if len(pointerFields) == resolved:
      if resolved != 0 :
        log.debug('%s pointers are fully resolved'%(self))
      self.pointerResolved = True
      #logging.getLogger('progressive').setLevel(logging.DEBUG)
      #self._aggregateStringPointersToArray()
      #logging.getLogger('progressive').setLevel(logging.INFO)
    else:
      self.pointerResolved = False
    return
  
  def _resolvePointerToStructField(self, field, structs_addrs, structCache):
    if len(structs_addrs) == 0:
      return None
    nearest_addr, ind = utils.closestFloorValue(field.value, structs_addrs)
    tgt_st = structCache[nearest_addr]
    if field.value in tgt_st:
      offset = field.value - nearest_addr
      for f in tgt_st.fields:
        if f.offset == offset:
          tgt_field = f
          return tgt_field
    return None
  
  def _aggregateStringPointersToArray(self):
    if not self.pointerResolved:
      raise ValueError('I should be resolved')
    pointerFields = self.getPointerFields()
    log.debug('aggregateStringPtr: start %lx'%(self.vaddr))
    myfields = sorted(self.fields)
    if len(myfields) < 2:
      log.debug('aggregateStringPtr: not so much fields')
      return
    array=[]
    #get the first pointer fields
    while len(myfields) > 1:
      myfields = [f for f in itertools.dropwhile(lambda x: self._isPointerToString(x) == False, myfields )]
      array = [f for f in itertools.takewhile(lambda x: self._isPointerToString(x) == True, myfields )]
      if len(array) > 1:
        log.debug('aggregateStringPtr: We just found %d pointers to String'%( len (array)))
        if len(myfields) > 0:
          f = myfields.pop(0) # if its not zero, its not ptr to string, we can skip it
          if f.isZeroes() and f.size == 4: # Null terminated array
            array.append(f)
            log.debug('aggregateStringPtr: We just found a null termination making a c_char_p[%d]'%( len(array) ))
        # create a array field
        field = field.Field(self, array[0].offset, FieldType.ARRAY_CHAR_P, len(array)*Config.WORDSIZE , False)
        field.element_size = Config.WORDSIZE
        field.elements = array
        # TODO border case f >=4, we need to cut f in f1[:4]+f2[4:]
        # clean self.fields
        for f in field.elements:
          self.fields.remove(f)
        self.fields.append(field)
        self.fields.sort()
    return
      
  def _isPointerToString(self, field):
    # pointer is Resolved
    if not field.isPointer():
      return False
    if hasattr(field,'_ptr_to_ext_lib'):
      return False      
    #if not hasattr(field,'_target_field'):
    #  return False
    return field._target_field.isString()
    
  
  def getPointerFields(self):
    return [f for f in self.fields if f.isPointer()]
    
  def getSignature(self):
    return ''.join([f.getSignature() for f in self.fields])
  
  def toString(self):
    #FIXME : self._fixGaps() ## need to TODO overlaps
    fieldsString = '[ \n%s ]'% ( ''.join([ field.toString('\t') for field in self.fields]))
    info = 'resolved:%s SIG:%s'%(self.resolved, self.getSignature())
    if len(self.getPointerFields()) != 0:
      info += ' pointerResolved:%s'%(self.pointerResolved)
    ctypes_def = '''
class %s(LoadableMembers):  # %s
  _fields_ = %s

''' % (self, info, fieldsString)
    return ctypes_def

  def __contains__(self, other):
    if isinstance(other, numbers.Number):
      # test vaddr in struct instance len
      if self.vaddr <= other <= self.vaddr+len(self):
        return True
      return False
    else:
      raise NotImplementedError()
      
  def __getitem__(self, i):
    return self.fields[i]
    
  def __len__(self):
    return len(self.bytes)

  def __cmp__(self, other):
    if not isinstance(other, AnonymousStructInstance):
      raise TypeError
    return cmp(self.vaddr, other.vaddr)
  
  def __str__(self):
    return 'AnonymousStruct_%s_%s'%(len(self), self.prefixname )
  


