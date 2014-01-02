#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

import haystack

from haystack import abouchet
from haystack import model


class TestRefreshX64(unittest.TestCase):
  """Validate refresh API on a linux x64 dump of ctypes7."""
  def setUp(self):
    self.address = 0x000000001b1e010
    self.memdumpname = 'test/src/test-ctypes7.64.dump'
    self.classname = 'test.src.ctypes7.struct_Node'
    self.known_heap = (0x00007f724c905000, 249856)

  def tearDown(self):
    self.mappings = None

  def test_refresh(self):
    ''' tests valid structure resfresh.'''
    # load empty shell with constraints in x64
    from test.src import ctypes7
    from test.src import ctypes7_gen64
    model.copyGeneratedClasses(ctypes7_gen64, ctypes7)
    model.registerModule(ctypes7)
    # apply constraints
    ctypes7.populate()
    self.assertEquals( len(ctypes7.struct_Node.expectedValues.keys()), 2)
    # string
    retstr = abouchet.show_dumpname( self.classname, self.memdumpname, self.address,rtype='string')
    self.assertIn("3735928559L,", retstr )
    self.assertIn("0x0000000001b1e010,", retstr )
    
    #python
    node, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.address,rtype='python')
    self.assertEquals( validated, True)
    self.assertEquals( node.val1, 0xdeadbeef)
    self.assertEquals( node.ptr2, self.address)


  def test_search(self):
    ''' tests valid structure show and invalid structure show.'''
    # load empty shell with constraints in x64
    from test.src import ctypes7
    from test.src import ctypes7_gen64
    model.copyGeneratedClasses(ctypes7_gen64, ctypes7)
    model.registerModule(ctypes7)
    # apply constraints
    ctypes7.populate()
    self.assertEquals( len(ctypes7.struct_Node.expectedValues.keys()), 2)
    
    for res in abouchet.search_dumpname( self.classname, self.memdumpname, rtype='string'):
        #self.assertEquals(len(res), 1)
        print res
        #instance, validated = res[0]
        #self.assertIsInstance(instance, object)
        #print hex(instance.val1)
        #self.assertEquals( instance.val1, 0xdeadbeef)
        #print instance.__dict__
        #self.assertEquals( instance.VirtualMemoryThreshold, 0xfe00)
        #self.assertEquals( instance.FrontEndHeapType, 0)
        #self.assertTrue(validated)    
    return 

class TestApiLinuxDumpX64(unittest.TestCase):
  """Validate API on a linux x64 dump of SSH."""
  def setUp(self):
    self.validAddress = '0x7f724c90d740'
    self.memdumpname = 'test/dumps/ssh/ssh.x64.6653.dump'
    self.classname = 'sslsnoop.ctypes_openssh.session_state'
    self.known_heap = (0x00007f724c905000, 249856)

  def tearDown(self):
    self.mappings = None

  def test_show(self):
    ''' tests valid structure show and invalid structure show.'''
    instance, validated = abouchet.show_dumpname( self.classname, self.memdumpname, long(self.validAddress,16))
    self.assertIsInstance(instance, object)
    self.assertEquals( instance.connection_in, 3)
    print instance.__dict__
    #self.assertEquals( instance.VirtualMemoryThreshold, 0xfe00)
    #self.assertEquals( instance.FrontEndHeapType, 0)
    #self.assertTrue(validated)    
    return 


class TestApiLinuxDump(unittest.TestCase):
  ''' test is the python API works. '''
  def setUp(self):
    self.memdumpname = 'test/dumps/ssh/ssh.1'
    self.classname = 'sslsnoop.ctypes_openssh.session_state'
    self.known_heaps = [ (0x00390000, 8956), (0x00540000, 868),
                    ( 0x00580000, 111933), (0x005c0000, 1704080) , 
                    ( 0x01ef0000, 604), (0x02010000, 61348), 
                    ( 0x02080000, 474949), (0x021f0000 , 18762),
                    ( 0x03360000, 604), (0x04030000 , 632),
                    ( 0x04110000, 1334), (0x041c0000 , 644),
                    # from free stuf
                    ( 0x0061a000, 1200),
                    ]

  def tearDown(self):
    self.mappings = None

  #_HEAP.expectedValues = {
  #  'Signature':[0xeeffeeff],
  #  'FrontEndHeapType': [0,1,2]
  #}

  def test_show(self):
    ''' tests valid structure show and invalid structure show.'''
    instance, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.known_heaps[0][0])
    self.assertTrue(validated)
    self.assertIsInstance(instance, object)
    self.assertEquals( instance.Signature, 0xeeffeeff)
    self.assertEquals( instance.VirtualMemoryThreshold, 0xfe00)
    self.assertEquals( instance.FrontEndHeapType, 0)
    
    instance, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.known_heaps[0][0]+1)
    self.assertFalse(validated)
    self.assertIsInstance(instance, object)
    self.assertNotEquals( instance.Signature, 0xeeffeeff)
    self.assertEquals(    instance.Signature, 0xeeffee) # 1 byte off
    self.assertNotEquals( instance.VirtualMemoryThreshold, 0xfe00)
    self.assertEquals(    instance.VirtualMemoryThreshold, 0xff0000fe)
    
    return 

class TestApiWin32Dump(unittest.TestCase):
  ''' test is the python API works. '''
  def setUp(self):
    self.memdumpname = 'test/dumps/putty/putty.1.dump'
    self.classname = 'haystack.reverse.win32.win7heap.HEAP'
    self.known_heaps = [ (0x00390000, 8956), (0x00540000, 868),
                    ( 0x00580000, 111933), (0x005c0000, 1704080) , 
                    ( 0x01ef0000, 604), (0x02010000, 61348), 
                    ( 0x02080000, 474949), (0x021f0000 , 18762),
                    ( 0x03360000, 604), (0x04030000 , 632),
                    ( 0x04110000, 1334), (0x041c0000 , 644),
                    # from free stuf
                    ( 0x0061a000, 1200),
                    ]

  def tearDown(self):
    self.mappings = None

  #_HEAP.expectedValues = {
  #  'Signature':[0xeeffeeff],
  #  'FrontEndHeapType': [0,1,2]
  #}

  def test_show(self):
    ''' tests valid structure show and invalid structure show.'''
    instance, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.known_heaps[0][0])
    self.assertTrue(validated)
    self.assertIsInstance(instance, object)
    self.assertEquals( instance.Signature, 0xeeffeeff)
    self.assertEquals( instance.VirtualMemoryThreshold, 0xfe00)
    self.assertEquals( instance.FrontEndHeapType, 0)
    
    instance, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.known_heaps[0][0]+1)
    self.assertFalse(validated)
    self.assertIsInstance(instance, object)
    self.assertNotEquals( instance.Signature, 0xeeffeeff)
    self.assertEquals(    instance.Signature, 0xeeffee) # 1 byte off
    self.assertNotEquals( instance.VirtualMemoryThreshold, 0xfe00)
    self.assertEquals(    instance.VirtualMemoryThreshold, 0xff0000fe)
    
    return 



if __name__ == '__main__':
  import sys
  #logging.basicConfig( stream=sys.stdout, level=logging.INFO )
  logging.basicConfig( stream=sys.stdout, level=logging.DEBUG )
  #logging.getLogger('basicmodel').setLevel(level=logging.DEBUG)
  #logging.getLogger('model').setLevel(level=logging.DEBUG)
  unittest.main(verbosity=0)


