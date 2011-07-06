#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import argparse, os, pickle, time, sys
import itertools
import operator

import statushandler
from .. import memory_dumper
from .. import memory_mapping
#from ..memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

import view
import widgets
import infomodel
from memmaptab import Ui_MemoryMappingWidget
from mainwindow import Ui_MainWindow


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s


class Dummy:
  ''' Dummy class with a len a a value.
  Quite useful to create Dummy structure of %d len.
  '''
  def __init__(self,len_, value=None):
    self._len_= len_
    self.value = value
  def __len__(self):
    return self._len_
  def __repr__(self):
    if not self.value is None:
      return repr(self.value)
    return 'Dummy'

class MemoryMappingWidget(QtGui.QWidget, Ui_MemoryMappingWidget):
  '''
    MemoryMappingWidget are used as tab. They are made of a QGraphicsView of 
    a QGraphicsScene representation of ONE memory mapping.
    Code is mostly duplicated from the mainwindow.ui .
  '''
  def __init__(self, mapping_name):
    QtGui.QWidget.__init__(self)
    # model
    self.mapping_name = mapping_name
    self._dirty = True
    self._init()

  def _init(self):
    if self._dirty:
      self.initData()
      self.setupUi()
      self.setupSignals()
      self._dirty = False

  def initData(self):
    self.pointers = None
    self.nullWords = None
    self.mapping = None
    self.mappings = None    
    self.scene = None
    self.sessionStateList = None
    
  def setupUi(self):
    #setupUi()
    super(MemoryMappingWidget,self).setupUi(self)
    # ours
    self.setObjectName(_fromUtf8(self.mapping_name))
    #change the graphics view.
    self.graphicsView = view.MemoryMappingView(self)
    self.graphicsView.setEnabled(True)
    sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
    sizePolicy.setHorizontalStretch(0)
    sizePolicy.setVerticalStretch(0)
    sizePolicy.setHeightForWidth(self.graphicsView.sizePolicy().hasHeightForWidth())
    self.graphicsView.setSizePolicy(sizePolicy)
    self.graphicsView.setObjectName(_fromUtf8("graphicsView"))
    self.gridLayout.addWidget(self.graphicsView, 0, 0, 1, 1)
    # mine
    self.pointers = QtGui.QGraphicsItemGroup() #self.graphicsView.GetScene().createItemGroup(items) 
    self.nullWords = QtGui.QGraphicsItemGroup()
    
  def setupSignals(self):
    #for each tab
    # signals - connect higlighting options
    self.connect(self.show_pointers, QtCore.SIGNAL('stateChanged(int)'), self._showPointers)
    self.connect(self.show_null, QtCore.SIGNAL('stateChanged(int)'), self._showNull)
 
  def _showPointers(self):
    log.debug('show_pointers')
    if not self.show_pointers.checkState():
      self.pointers.hide()
    else:
      self.pointers.show()
    
  def _showNull(self):
    log.debug('show_null')
    if not self.show_null.checkState():
      self.nullWords.hide()
    else:
      self.nullWords.show()

  
  def loadMapping(self, mapping, mappings):
    ''' 
    update the widget with a new mapping
    we also have to keep a reference to all mappings to be able to search for structures..
    '''
    self._init() # pass if not self._dirty
    self.mapping = mapping
    self.mappings = mappings
    if self.mapping not in self.mappings:
      raise ValueError('mapping not in mapping list.')
    # init the view
    self.graphicsView.loadMapping(mapping)
    self.scene = self.graphicsView.GetScene()
    self._dirty = True # reload will clean it    
    # start
    log.debug('parsing %s mapping'%(self.mapping_name))
    found = 0 
    nb = self.mapping.end - self.mapping.start
    tmpnull = []
    for offset in xrange(0,nb,4):
      i = offset + self.mapping.start
      word = self.mapping.readWord(i)
      # find pointers
      if word in self.mapping:
        found +=1
        self.pointers.addToGroup(widgets.Word(offset,word,scene = self.scene, color = QtCore.Qt.red) )
      elif word == 0: # find null values
        tmpnull.append(offset/4) # save offset aligned indices, cause i don't get "lambda (i,x):i-x" . Shame on me.
    # filter and 
    nb = 0
    should = 0
    for k, g in itertools.groupby(enumerate(tmpnull), lambda (i,x):i-x):
      rang = [v*4 for v in map(operator.itemgetter(1), g)] # still not getting lambdas....
      # add an structure of len(range)*4 bytes
      self.nullWords.addToGroup(widgets.Structure(rang[0], Dummy(4*len(rang),value=0),scene = self.scene, color = QtCore.Qt.gray) )
      log.debug("Adding a zero struct of %d len"%( len(rang) ))
      nb+=1
      should+=len(rang)
    log.debug('Created %d qrect instead of %d words'%(nb,should))
    # fill the scene
    self.scene.addItem(self.pointers)
    self.scene.addItem(self.nullWords)
    self.pointers.hide()
    self.pointers.setZValue(10) # zValue has to be  > 0
    #self.pointers.setFlag(QtGui.QGraphicsItem.ItemIsSelectable, False)
    self.nullWords.hide()
    self.nullWords.setEnabled(False)
    self.nullWords.setZValue(1) # zValue has to be  > 0
    # still not letting me trough the boundingRect
    self.nullWords.setToolTip('Null value words')
    return

  def searchStructure(self, structType='sslsnoop.ctypes_openssh.session_state'):
    ''' 
    return size of structure and list of addresses and values )
    '''
    from haystack import abouchet
    import ctypes
    #import sslsnoop #?
    instances = abouchet.searchIn(structType, mappings=self.mappings, targetMappings=[self.mapping] ,maxNum=999)
    if len(instances) > 0:
      log.debug('received %d struct of size %d'%(len(instances),len(instances[0][0])))
    # init graphical element
    instanceList = []
    for value, addr in instances:
      offset = addr - self.mapping.start
      instanceList.append(widgets.Structure( offset, value, color=QtCore.Qt.green, scene=self.scene))
    # fill the scene
    #self.scene.addItem(instanceList)
    log.debug('Found %d instances'%(len(instances)) )
    gitemgroup = QtGui.QGraphicsItemGroup(scene=self.scene)
    for s in instanceList:
      gitemgroup.addToGroup(s)
    gitemgroup.setZValue(20) # zValue has to be  > 0
    # add self.instanceList to
    if len(instanceList) >0 :
      self.showInfo(instanceList[0])
    return instanceList,gitemgroup

  def showInfo(self, structure):
    log.info('show info on %s'%(structure))
    pyObj = structure.value
    rows = [ (k,str(v)) for k,v,typ in pyObj]
    log.debug('self.info_tableview populated with %d rows'%(len(rows)))    
    # set the table model
    header = ['field', 'value']
    tm = infomodel.StructureInfoTableModel(rows, header, self) 
    self.info_tableview.setModel(tm)
    # set the font
    font = QtGui.QFont("Courier New", 8)
    self.info_tableview.setFont(font)
    # hide vertical header
    vh = self.info_tableview.verticalHeader()
    vh.setVisible(False)
    # set horizontal header properties
    hh = self.info_tableview.horizontalHeader()
    hh.setStretchLastSection(True)
    # set column width to fit contents
    self.info_tableview.resizeColumnsToContents()
    # set row height
    nrows = len(rows)
    for row in xrange(nrows):
        self.info_tableview.setRowHeight(row, 18)
    # enable sorting
    self.info_tableview.setSortingEnabled(True)
    return



class MyMain(QtGui.QMainWindow, Ui_MainWindow):
  '''
    Main Window app.
    Status bar + tabwidget mostly.
  '''
  sessionStateList = None
  pointers = None
  nullWords = None
  def __init__(self, argv, parent=None):
    QtGui.QMainWindow.__init__(self, parent)
    # draw the window
    # populate useful data
    self.setupUi(self)
    #widgets.Structure( 2000, Dummy(12000), color=QtCore.Qt.green, scene=self.scene)
    self.argv = argv
    # if command line, to command line
    if hasattr(self.argv,'dumpfile'):
      self.openDump()
      self.currentTab().searchStructure()

  def setupUi(self,me):
    super(MyMain,self).setupUi(self)
    # regroup tabs in a dict
    self.memorydump_tabs = dict()
    # connect menu
    self.connect(self.menu_file_exit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
    self.connect(self.menu_file_open, QtCore.SIGNAL('triggered()'), self.openDump)
    self.connect(self.menu_search_structure, QtCore.SIGNAL('triggered()'), self.searchStructure)
    self.tabWidget.removeTab(0)    
    self.tabWidget.removeTab(0)
    # plug logging to the statusBar
    statusbarhandler = statushandler.StatusBarHandler(self.statusBar())
    logging.getLogger('haystack').addHandler(statusbarhandler)
    logging.getLogger('dumper').addHandler(statusbarhandler)
    logging.getLogger('gui').addHandler(statusbarhandler)
    logging.getLogger('view').addHandler(statusbarhandler)
    # be nice
    self.statusBar().showMessage('Please Open a memory dump')

  def make_memory_tab(self, dump_name, mapping, mappings):
    if dump_name in self.memorydump_tabs:
      # switch to tab
      #self.throw
      log.info('dump %s is already opened'%(dump_name))
      return
    
    tab = MemoryMappingWidget(dump_name)
    log.debug('Tab Created')
    self.statusBar().showMessage('Tab Created')
    self.tabWidget.addTab(tab, _fromUtf8(dump_name))
    self.tabWidget.setTabText(self.tabWidget.indexOf(tab), QtGui.QApplication.translate("MainWindow", dump_name, None, QtGui.QApplication.UnicodeUTF8))
    nb = self.tabWidget.count()
    self.tabWidget.setCurrentIndex(nb-1)
    log.debug('Switched to tab %d'%(nb))
    self.memorydump_tabs[dump_name] = tab
    log.debug('Populate the QGraphicsScene')
    tab.loadMapping(mapping, mappings)
    log.debug('QGraphicsScene populated')
    return

  def openDump(self):
    # load memorymapping
    mappings = memory_dumper.load(self.argv)
    self.mappings = mappings
    # TODO : make a mapping chooser and kick self.heap and self.mappings
    self.heap = [m for m in self.mappings if m.pathname == '[heap]'][0]
    self.make_memory_tab( os.path.sep.join( [os.path.basename(self.argv.dumpfile.name),self.heap.pathname]), self.heap, self.mappings)
    log.info('Dump opened')
    return

  def searchStructure(self):
    import searchview
    #save a ref ?
    self.searchStructureDialog = searchview.SearchStructDialog(self)
    self.searchStructureDialog.show()
    return
  
  def currentTab(self):
    return self.tabWidget.currentWidget()

  
  def closeEvent(self, event):
    #debug
    event.accept()
    return
    #
    reply = QtGui.QMessageBox.question(self, 'Message',
        "Are you sure to quit?", QtGui.QMessageBox.Yes | 
        QtGui.QMessageBox.No, QtGui.QMessageBox.No)

    if reply == QtGui.QMessageBox.Yes:
      event.accept()
    else:
      event.ignore()
    


 


def dropToInteractive():
  import code
  code.interact(local=locals())

              
def gui(opt):
  app = QtGui.QApplication(sys.argv)

  #mappings = memory_dumper.load(opt)
  mappings = None
  root = MyMain(opt)
  root.show()

  sys.exit(app.exec_())

def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-gui', description='Graphical tool.')
  rootparser.add_argument('--dumpfile', type=argparse.FileType('rb'), action='store', help='Source memdump')
  rootparser.add_argument('--lazy', action='store_const', const=True , help='Lazy load')
  rootparser.set_defaults(func=gui)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  logging.getLogger('ctypes_openssh').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
