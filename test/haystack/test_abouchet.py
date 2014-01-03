#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests haystack.utils ."""

import logging
import unittest

import haystack

from haystack import abouchet
from haystack import model
from haystack import types


class SrcTests(unittest.TestCase):
    def _load_offsets(self, dumpname):
        """read <dumpname>.stdout to get offsets given by the binary."""
        offsets = dict()
        for line in open('%s.stdout'%(dumpname[:-len('.dump')]),'rb').readlines():
            fields = line.split(' ')
            k,v = fields[0],int(fields[1].strip(),16)
            if k not in offsets:
                offsets[k]=[]
            offsets[k].append(v)
        return offsets

class Test7_x32(SrcTests):
  """Validate abouchet API on a linux x32 dump of ctypes7.
  Mainly tests cross-arch c_void_p."""
  def setUp(self):
    model.reset()
    types.reload_ctypes(4,4,8)
    self.memdumpname = 'test/src/test-ctypes7.32.dump'
    self.classname = 'test.src.ctypes7.struct_Node'
    offsets = self._load_offsets(self.memdumpname)
    self.address = offsets['test1'][0] #0x8f40008
    # load layout in x32
    from test.src import ctypes7
    from test.src import ctypes7_gen32
    model.copyGeneratedClasses(ctypes7_gen32, ctypes7)
    model.registerModule(ctypes7)
    # apply constraints
    ctypes7.populate()

  def tearDown(self):
    self.mappings = None

  def test_refresh(self):
    ''' tests valid structure refresh.'''
    from test.src import ctypes7
    self.assertEquals( len(ctypes7.struct_Node.expectedValues.keys()), 2)
    # string
    retstr = abouchet.show_dumpname( self.classname, self.memdumpname, self.address,rtype='string')
    self.assertIn("3735928559L,", retstr ) # 0xdeadbeef
    self.assertIn("0x08f40008,", retstr )
    
    #python
    node, validated = abouchet.show_dumpname( self.classname, self.memdumpname, self.address,rtype='python')
    self.assertEquals( validated, True)
    self.assertEquals( node.val1, 0xdeadbeef)
    self.assertEquals( node.ptr2, self.address)


  def test_search(self):
    ''' tests valid structure show and invalid structure show.'''
    from test.src import ctypes7
    self.assertEquals( len(ctypes7.struct_Node.expectedValues.keys()), 2)
    
    retstr = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='string')
    self.assertIn("3735928559L,", retstr )
    self.assertIn("0x08f40008,", retstr )
    
    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)
    
    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, maxnum=10, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)
    return 


class Test7_x64(SrcTests):
  """Validate abouchet API on a linux x64 dump of ctypes7.
  Mainly tests cross-arch c_void_p."""
  def setUp(self):
    model.reset()
    types.reload_ctypes(8,8,16)
    self.memdumpname = 'test/src/test-ctypes7.64.dump'
    self.classname = 'test.src.ctypes7.struct_Node'
    offsets = self._load_offsets(self.memdumpname)
    self.address = offsets['test1'][0] # 0x000000001b1e010
    # load layout in x64
    from test.src import ctypes7
    from test.src import ctypes7_gen64
    model.copyGeneratedClasses(ctypes7_gen64, ctypes7)
    model.registerModule(ctypes7)
    # apply constraints
    ctypes7.populate()

  def tearDown(self):
    self.mappings = None

  def test_refresh(self):
    ''' tests valid structure refresh.'''
    from test.src import ctypes7
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
    from test.src import ctypes7
    self.assertEquals( len(ctypes7.struct_Node.expectedValues.keys()), 2)
    
    retstr = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='string')
    self.assertIn("3735928559L,", retstr )
    self.assertIn("0x0000000001b1e010,", retstr )
    
    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)

    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, maxnum=10, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)
    return 


class Test6_x32(SrcTests):
  """Validate abouchet API on a linux x32 dump of ctypes6.
  Mainly tests cross-arch POINTER to structs and c_char_p."""
  def setUp(self):
    import sys
    model.reset()
    types.reload_ctypes(4,4,8)
    self.memdumpname = 'test/src/test-ctypes6.32.dump'
    self.node_structname = 'test.src.ctypes6.struct_Node'
    self.usual_structname = 'test.src.ctypes6.struct_usual'
    offsets = self._load_offsets(self.memdumpname)
    self.address1 = offsets['test1'][0] # struct_usual
    self.address2 = offsets['test2'][0] # struct_Node
    self.address3 = offsets['test3'][0] # struct_Node
    # load layout in x32
    from test.src import ctypes6
    from test.src import ctypes6_gen32
    model.copyGeneratedClasses(ctypes6_gen32, ctypes6)
    model.registerModule(ctypes6)
    # apply constraints
    ctypes6.populate()

  def tearDown(self):
    self.mappings = None

  def test_refresh(self):
    ''' tests valid structure refresh.'''
    from test.src import ctypes6
    self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)
    if False:
        # string
        retstr = abouchet.show_dumpname(self.usual_structname, self.memdumpname,
                                        self.address1, rtype='string')
        print 'Y', model.getRef(ctypes6.struct_entry, 0x94470ac)
        return
        import ctypes
        self.assertIn('CTypesProxy-4:4:8', '%s'%ctypes)
        self.assertIn(str(0x0aaaaaaa), retstr) # 0xaaaaaaa/178956970L
        self.assertIn(str(0x0ffffff0), retstr)
        self.assertIn('"val2b": 0L,', retstr)
        self.assertIn('"val1b": 0L,', retstr)
        #print retstr
        #return
        #usual->root.{f,b}link = &node1->list; # offset list is 4 bytes
        from haystack import utils
        node1_list_addr = utils.formatAddress(self.address2+4)
        self.assertIn('"flink": { #(%s'%(node1_list_addr), retstr)
        self.assertIn('"blink": { #(%s'%(node1_list_addr), retstr)
    
    
    #python
    usual, validated = abouchet.show_dumpname(self.usual_structname,
                                              self.memdumpname,
                                              self.address1, rtype='python')
    self.assertEquals(validated, True)
    self.assertEquals(usual.val1, 0x0aaaaaaa)
    self.assertEquals(usual.val2, 0x0ffffff0)
    self.assertEquals(usual.txt, 'This a string with a test this is a test '
                                 'string')


    #print 'usual.root.flink', usual.root.flink
    #print 'usual.root.blink', usual.root.blink
    #print 'usual.root.flink.flink', usual.root.flink.flink
    #import code
    #code.interact(local=locals())
    #return
    #python 2 struct Node
    node1, validated = abouchet.show_dumpname(self.node_structname,
                                              self.memdumpname,
                                              self.address2, rtype='python')
    self.assertEquals(validated, True)
    self.assertEquals(node1.val1, 0xdeadbeef)
    self.assertEquals(node1.val2, 0xffffffff)

    node2, validated = abouchet.show_dumpname(self.node_structname,
                                              self.memdumpname,
                                              self.address3, rtype='python')
    self.assertEquals(validated, True)
    self.assertEquals(node2.val1, 0xdeadbabe)
    self.assertEquals(node2.val2, 0xffffffff)

    
    #FIXME: if you delete the Heap memorymap, 
    # all references in the model are invalided
    
    print 'Y', model.getRef(ctypes6.struct_entry, 0x94470ac)

    #x = usual._mappings.getHeap()

    #print node1.toString()
    #import code
    #code.interact(local=locals())
    #print node2.toString()
    # TODO the listmodel test shoudl test if references have been loaded
    # without searching for them.


  def test_search(self):
    ''' tests valid structure show and invalid structure show.'''
    from test.src import ctypes6
    self.assertEquals( len(ctypes6.struct_Node.expectedValues.keys()), 2)
    
    retstr = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='string')
    self.assertIn("3735928559L,", retstr )
    self.assertIn("0x08f40008,", retstr )
    
    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)
    
    #python
    results = abouchet.search_dumpname( self.classname, self.memdumpname, maxnum=10, rtype='python')
    self.assertEquals( len(results), 1)
    for node, offset in results:
        self.assertEquals( offset, self.address)
        self.assertEquals( node.val1, 0xdeadbeef)
        self.assertEquals( node.ptr2, self.address)
    return 


class Test6_x64(SrcTests):
  """Validate abouchet API on a linux x64 dump of ctypes6.
  Mainly tests cross-arch POINTER to structs and c_char_p."""
  def setUp(self):
    model.reset()
    types.reload_ctypes(8,8,16)
    self.memdumpname = 'test/src/test-ctypes6.64.dump'
    self.node_structname = 'test.src.ctypes6.struct_Node'
    self.usual_structname = 'test.src.ctypes6.struct_usual'
    offsets = self._load_offsets(self.memdumpname)
    self.address1 = offsets['test1'][0] # struct_usual
    self.address2 = offsets['test2'][0] # struct_Node
    self.address3 = offsets['test3'][0] # struct_Node
    # load layout in x64
    from test.src import ctypes6
    from test.src import ctypes6_gen64
    model.copyGeneratedClasses(ctypes6_gen64, ctypes6)
    model.registerModule(ctypes6)
    # apply constraints
    ctypes6.populate()

  def tearDown(self):
    self.mappings = None

  def test_refresh(self):
    ''' tests valid structure refresh.'''
    from test.src import ctypes6
    self.assertEquals(len(ctypes6.struct_Node.expectedValues.keys()), 2)
    # string
    retstr = abouchet.show_dumpname(self.usual_structname, self.memdumpname,
                                    self.address1, rtype='string')
    import ctypes
    self.assertIn('CTypesProxy-8:8:16', '%s'%ctypes)
    self.assertIn(str(0x0aaaaaaa), retstr) # 0xaaaaaaa/178956970L
    self.assertIn(str(0x0ffffff0), retstr)
    self.assertIn('"val2b": 0L,', retstr)
    self.assertIn('"val1b": 0L,', retstr)
    
    #python
    usual, validated = abouchet.show_dumpname(self.usual_structname,
                                              self.memdumpname,
                                              self.address1, rtype='python')
    self.assertEquals( validated, True)
    self.assertEquals( usual.val1, 0x0aaaaaaa)
    self.assertEquals( usual.val2, 0x0ffffff0)
    self.assertEquals(usual.txt, 'This a string with a test this is a test '
                                 'string')



@unittest.skip('')
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


@unittest.skip('')
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

@unittest.skip('')
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
  #logging.basicConfig( stream=sys.stdout, level=logging.DEBUG )
  #logging.getLogger('basicmodel').setLevel(level=logging.DEBUG)
  #logging.getLogger('model').setLevel(level=logging.DEBUG)
  logging.getLogger('memory_mapping').setLevel(level=logging.INFO)
  unittest.main(verbosity=0)


