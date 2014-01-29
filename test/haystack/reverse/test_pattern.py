#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import struct
import operator
import os
import unittest

from haystack import model
from haystack import memory_mapping
from haystack.reverse import pattern
from haystack import config


def accumulate(iterable, func=operator.add):
  it = iter(iterable)
  total = next(it)
  yield total
  for element in it:
    total = func(total, element)
    yield total

def makeMMap( seq, start=Config.MMAP_START, offset=Config.STRUCT_OFFSET  ):
  nsig = [offset]
  nsig.extend(seq)
  indices = [ i for i in accumulate(nsig)]
  dump = [] #b''
  for i in range(0,Config.MMAP_LENGTH, Config.get_word_size()): 
    if i in indices:
      dump.append( struct.pack('L',start+i) )
    else:
      dump.append( struct.pack('L',0x2e2e2e2e) )
  
  if len(dump) != Config.MMAP_LENGTH/Config.get_word_size() :
    raise ValueError('error on length dump %d '%( len(dump) ) )  
  dump2 = ''.join(dump)
  if len(dump)*Config.get_word_size() != len(dump2):
    raise ValueError('error on length dump %d dump2 %d'%( len(dump),len(dump2)) )
  stop = start + len(dump2)
  mmap = memory_mapping.MemoryMapping(start, stop, '-rwx', 0, 0, 0, 0, 'test_mmap')
  mmap2= memory_mapping.LocalMemoryMapping.fromBytebuffer( mmap, dump2)
  return mmap2


def makeSignature(seq):
  mmap = makeMMap(seq)
  mappings = memory_mapping.Mappings([mmap], 'test')
  sig = pattern.PointerIntervalSignature(mappings, 'test_mmap', Config)
  return sig  

class TestSignature(unittest.TestCase):

  def setUp(self):
    self.Config = config.make_config_linux32() # forcing it on these unittest


    self.Config.MMAP_START = 0x0c00000
    self.Config.MMAP_STOP =  0x0c01000
    self.Config.MMAP_LENGTH = 4096
    self.Config.STRUCT_OFFSET = 44
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.mmap = makeMMap(self.seq)
    self.name = 'test_dump_1'
    self.sig = makeSignature(self.seq)

  def test_init(self):
    # forget about the start of the mmap  ( 0 to first pointer value) , its irrelevant
    self.assertEqual( list(self.sig.sig[1:]) , self.seq)

  def test_getAddressForPreviousPointer(self):
    self.assertEqual( self.sig.getAddressForPreviousPointer(0) , Config.MMAP_START)
    self.assertEqual( self.sig.getAddressForPreviousPointer(1) , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.sig.getAddressForPreviousPointer(2) , Config.MMAP_START+Config.STRUCT_OFFSET + 4)

  def test_len(self):
    self.assertEqual( len(self.sig) , len(self.seq)+1 )
  
# def tearDown(self):
#   os.remove('test_dump_1.pinned')
#   os.remove('test_dump_1.pinned.vaddr')
#   os.remove('test_signature_1.pinned')
#   os.remove('test_signature_1.pinned.vaddr')
      


class TestPinnedPointers(unittest.TestCase):

  def setUp(self):
    # PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 1 # offset of the pinned pointer sequence in the sig
    self.name = 'test_dump_1'
    self.sig = makeSignature(self.seq)
    self.pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)

  def test_init(self):
    self.assertEqual( self.pp.sequence, list(self.sig.sig[self.offset: self.offset+len(self.pp)]))

  def test_pinned(self):
    self.assertEqual( self.pp.pinned() , self.seq)
    self.assertEqual( len(self.pp.pinned(5)) , 5 )
    self.assertEqual( self.pp.pinned(3) , self.seq[0:3] )

  def test_len(self):
    len_seq = len(self.seq) 
    self.assertEqual( len(self.pp) , len_seq)

  def test_structlen(self):
    len_struct = sum(self.seq) +4
    self.assertEqual( self.pp.structLen() , len_struct)

  def test_cmp(self):
    seq = [4,4,8,128,4,8,4,4,12]
    pp1 = pattern.PinnedPointers(seq[1:], self.sig, self.offset+1)
    pp2 = pattern.PinnedPointers(seq[1:-1], self.sig, self.offset+1)
    pp3 = pattern.PinnedPointers(seq[:-1], self.sig, self.offset+1)
    pp4 = pattern.PinnedPointers(seq[:], self.sig, self.offset+1)

    seq = [4,8,4,128,4,8,4,4,12]
    pp5 = pattern.PinnedPointers(seq, self.sig, self.offset)

    self.assertNotEqual( pp1, self.pp)
    self.assertNotEqual( pp2, self.pp)
    self.assertNotEqual( pp3, self.pp)
    self.assertEqual( pp4, self.pp)
    self.assertNotEqual( pp5, self.pp)

 # def test_contains(self):
 #   seq = [4,4,8,128,4,8,4,4,12]
 #   pp1 = pattern.PinnedPointers(seq[1:], self.sig, self.offset+1)
 #   pp2 = pattern.PinnedPointers(seq[1:-1], self.sig, self.offset+1)
 #   pp3 = pattern.PinnedPointers(seq[:-1], self.sig, self.offset+1)
 #   pp4 = pattern.PinnedPointers(seq[:], self.sig, self.offset+1)#
 #   seq = [4,8,4,128,4,8,4,4,12]
 #   pp5 = pattern.PinnedPointers(seq, self.sig, self.offset)
 #
 #   #self.assertRaises( ValueError, r'ValueError', seq in self.pp )
 #   self.assertIn( pp1 , self.pp )
 #   self.assertIn( pp2 , self.pp )
 #   self.assertIn( pp3 , self.pp )
 #   self.assertIn( pp4 , self.pp )
 #   self.assertIn( pp5 , self.pp )

  def test_getAddress(self):
    self.assertEqual( self.pp.getAddress() , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.pp.getAddress(0) , Config.MMAP_START+Config.STRUCT_OFFSET)
    self.assertEqual( self.pp.getAddress(1) , Config.MMAP_START+Config.STRUCT_OFFSET+sum(self.seq[:1]))
    self.assertEqual( self.pp.getAddress(2) , Config.MMAP_START+Config.STRUCT_OFFSET+sum(self.seq[:2]))



class TestAnonymousStructRange(unittest.TestCase):

  def setUp(self):
    # .....PP.P...[..].PP.PPP..P
    self.seq = [4,4,8,128,4,8,4,4,12]
    self.offset = 1 # we need to skip the start -> first pointer part
    self.name = 'struct_1'
    self.sig = makeSignature(self.seq)
    self.pp = pattern.PinnedPointers(self.seq, self.sig, self.offset)
    self.astruct = pattern.AnonymousStructRange(self.pp)

  def test_len(self):
    len_struct = sum(self.seq) + 4
    self.assertEqual( len(self.astruct) , len_struct)
    self.assertEqual( len(self.astruct) , self.pp.structLen() )
    
  def test_getPointersAddr(self):
    ret = self.astruct.getPointersAddr()
    tmp = [Config.MMAP_START, Config.STRUCT_OFFSET]
    tmp.extend(self.seq)
    addresses = [i for i in accumulate(tmp)]
    addresses.pop(0) # ignore address of start mmap

    self.assertEqual( len(ret) , len(addresses))
    self.assertEqual( ret , addresses)

  def test_getPointersValues(self):
    ret = self.astruct.getPointersValues()
    addrs = self.astruct.getPointersAddr()
    tmp = [Config.MMAP_START, Config.STRUCT_OFFSET]
    tmp.extend(self.seq)
    addresses = [i for i in accumulate(tmp)]
    addresses.pop(0) # ignore address of start mmap
    
    self.assertEqual( len(ret) , len(addresses))
    self.assertEqual( len(ret) , len(addrs))    
    # pointer value is the pointer vaddr on first test case
    for addr,val in zip(addrs,ret):
      memval = self.sig.mmap.readWord(addr)
      self.assertEqual( memval, val)
      self.assertEqual( addr , val)

  def test_contains(self):
    START = Config.MMAP_START+Config.STRUCT_OFFSET
    STOP = START+len(self.astruct)
    
    self.assertIn( START, self.astruct)
    self.assertIn( START+1, self.astruct)
    self.assertIn( STOP, self.astruct)
    self.assertIn( STOP-1, self.astruct)

    self.assertNotIn( STOP+1, self.astruct)
    self.assertNotIn( START-1, self.astruct)
  

class TestFunctions(unittest.TestCase):
  def test_findPattern_recursive_1(self):
    sig = '''P4I4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z'''\
    '''4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u4z4P4I4u172z4I4T'''\
    '''8z4I4z4I4T8z4I4z4I4T8z4I4z4I4T8z4I4z4u4z26336'''
    sig_res = 'P4 (I4){2}  (u4z4P4I4){21} u172z4 (I4T8z4I4z4){4} u4z26336'

    self.assertEquals ( pattern.findPatternText(sig,2), sig_res)
    
  def test_findPattern_recursive_2(self):
    sig = '''P4i4i4u9z8i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4T5I4P4i4T5I4P4i4I4I4P4i4T5'''\
    '''I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4'''\
    '''I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4I4I4P4i4T5I4P4I4i4'''
    sig_res = 'P4 (i4){2} u9z8i4 (I4I4P4i4){7}  (T5I4P4i4){2}  (I4){2} P4i4T5I4P4i4 (I4I4P4i4){17} T5I4P4I4i4'

    self.assertEquals ( pattern.findPatternText(sig,2), sig_res)

  def test_findPattern_recursive_3(self):
    sig = '''I4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4z12'''
    sig_res = 'I4 (i4){31} z12'
    #print pattern.findPatternText( sig,2)
    #self.assertRaises ( ValueError, pattern.findPatternText , sig,2) # why ?
    self.assertEquals ( pattern.findPatternText(sig,2), sig_res)

  #def test_findPattern_recursive_3b(self):
  #  sig = '''I4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4z2'''
  #  sig_res = 'I4 (i4){31} z2'
  #  self.assertEquals ( pattern.findPatternText(sig,2), sig_res)

  def test_findPattern_recursive_4(self):
    sig = '''123321444567444567444567444567111123'''
    sig_res = '123321 (444567){4} 111123'
    self.assertEquals ( pattern.findPatternText(sig,3), sig_res)

  def test_findPattern_recursive_5(self):
    sig = '''AAABABABABBAAABBBBABACBCBCBCBABCBABABC'''
    sig_res = ' (A){2}  (AB){4} B (A){3}  (B){3}  (BA){2}  (CB){3}  (CBAB){2} ABC'
    self.assertEquals ( pattern.findPatternText(sig,1), sig_res)

  def test_findPattern_recursive_6(self):
    sig = '''aaaaa1111bbbccda2a2a2a2a2b1cb1cb1cb1cabcdabcdabcdabcdpooiiiuuuuyyyyy'''
    sig_res = ' (a){5}  (1){4}  (b){3}  (c){2} d (a2){5}  (b1c){4}  (abcd){4} p (o){2}  (i){3}  (u){4}  (y){5} '
    self.assertEquals ( pattern.findPatternText(sig,1), sig_res)

  def test_findPattern_recursive_7(self):
    sig = '''aaaaa1111bbbccda2a2a2a2a2b1cb1cb1cb1cabcdabcdabcdabcdpooiiiuuuuyyyyy'''
    sig_res = ' (a){5}  (1){4}  (b){3} ccd (a2){5}  (b1c){4}  (abcd){4} poo (i){3}  (u){4}  (y){5} '
    self.assertEquals ( pattern.findPatternText(sig,1,3), sig_res)

  #def test_findPattern_recursive_8(self):
  #  sig = '''I4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4z12'''
  #  sig_res = 'I4 (i4){31} z12'
  #  self.assertRaises ( ValueError, pattern.findPatternText , sig,2,4)

  def test_findPattern_recursive_8b(self):
    sig = '''I4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4z1'''
    sig_res = 'I4 (i4){31} z1'
    self.assertEquals ( pattern.findPatternText(sig,2,4), sig_res)

  def test_findPattern_recursive_9(self):
    sig = '''aaaaa1111bbbccda2a2a2a2a2b1cb1cb1cb1cabcdabcdabcdabcdpooiiiuuuuyyyyy'''
    sig_res = ' (a){5} 1111bbbccd (a2){5} b1cb1cb1cb1cabcdabcdabcdabcdpooiiiuuuu (y){5} '
    self.assertEquals ( pattern.findPatternText(sig,1,5), sig_res)

class TestPatternEncoder(unittest.TestCase):
  
  def test_makePattern_1(self):
    sig = ['P4','I4','I4']+(['u4','z12','P4','I4']*21) +[ 'u172','z12']+ (['I4','T8','z12','I4','z12']*4) +['u4','z26336']
    encoder = pattern.PatternEncoder(sig,3)
    #sig_res = 'P4 (I4){2}  (u4z12P4I4){21} u172z12 (I4T8z12I4z12){4} u4z26336'
    sig_res = [(1,'P4'),(1,'I4'),(1,'I4'),(21,['u4','z12','P4','I4']), (1,'u172'), (1,'z12'), (4,['I4','T8','z12','I4','z12']), (1,'u4'), (1,'z26336')]

    self.assertEquals ( encoder.makePattern(), sig_res)





if __name__ == '__main__':
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
