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

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

from mainwindow import Ui_MainWindow

class Dummy:
  def __init__(self,len_, value=None):
    self._len_= len_
    self.value = value
  def __len__(self):
    return self._len_
  def __repr__(self):
    if not self.value is None:
      return repr(value)
    return 'Dummy'

class MemoryDumpWidget(QtGui.QWidget):
  def __init__(self, mapping_name):
    ''' from mainwindow.ui '''
    QtGui.QWidget.__init__(self)
    # model
    self.mapping_name = mapping_name
    self._dirty = True
    self._init()

  def _init(self):
    if self._dirty:
      self.initData()
      self.setupUi()
      self.retranslateUi()
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
    #UI    
    self.tab = self
    self.tab.setObjectName(_fromUtf8(self.mapping_name))
    self.gridLayout_3 = QtGui.QGridLayout(self.tab)
    self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
    # make the view
    self.view = view.MemoryMappingView(self.tab)
    self.view.setObjectName(_fromUtf8("view"))
    self.gridLayout_3.addWidget(self.view, 0, 0, 1, 1)
    # back to normal
    self.groupBox = QtGui.QGroupBox(self.tab)
    self.groupBox.setEnabled(True)
    sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
    sizePolicy.setHorizontalStretch(0)
    sizePolicy.setVerticalStretch(0)
    sizePolicy.setHeightForWidth(self.groupBox.sizePolicy().hasHeightForWidth())
    self.groupBox.setSizePolicy(sizePolicy)
    self.groupBox.setMaximumSize(QtCore.QSize(16777215, 70))
    self.groupBox.setObjectName(_fromUtf8("groupBox"))
    self.show_null = QtGui.QCheckBox(self.groupBox)
    self.show_null.setGeometry(QtCore.QRect(17, 25, 125, 16))
    self.show_null.setObjectName(_fromUtf8("show_null"))
    self.show_pointers = QtGui.QCheckBox(self.groupBox)
    self.show_pointers.setGeometry(QtCore.QRect(17, 45, 125, 16))
    self.show_pointers.setObjectName(_fromUtf8("show_pointers"))
    self.show_search = QtGui.QCheckBox(self.groupBox)
    self.show_search.setGeometry(QtCore.QRect(590, 0, 161, 36))
    self.show_search.setObjectName(_fromUtf8("show_search"))
    self.gridLayout_3.addWidget(self.groupBox, 1, 0, 1, 1)
    # mine
    self.pointers = QtGui.QGraphicsItemGroup() #self.view.GetScene().createItemGroup(items) 
    self.nullWords = QtGui.QGraphicsItemGroup()

  def retranslateUi(self):
    self.groupBox.setTitle(QtGui.QApplication.translate("MainWindow", "Highlight", None, QtGui.QApplication.UnicodeUTF8))
    self.show_null.setText(QtGui.QApplication.translate("MainWindow", "Null values", None, QtGui.QApplication.UnicodeUTF8))
    self.show_pointers.setText(QtGui.QApplication.translate("MainWindow", "Pointer values", None, QtGui.QApplication.UnicodeUTF8))
    self.show_search.setText(QtGui.QApplication.translate("MainWindow", "Find session_state", None, QtGui.QApplication.UnicodeUTF8))
    
  def setupSignals(self):
    #for each tab
    # signals - connect higlighting options
    self.connect(self.show_pointers, QtCore.SIGNAL('stateChanged(int)'), self._showPointers)
    self.connect(self.show_null, QtCore.SIGNAL('stateChanged(int)'), self._showNull)
    self.connect(self.show_search, QtCore.SIGNAL('stateChanged(int)'), self._showSessionState)
 
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

  def _showSessionState(self):
    log.debug('show session_state')
    if self.sessionStateList is None:
      self.searchSessionState()
    if not self.show_search.checkState():
      self.sessionStateList.hide()
    else:
      self.sessionStateList.show()
  
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
    self.view.loadMapping(mapping)
    self.scene = self.view.GetScene()
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


  def searchSessionState(self):
    ''' return size of structure and list of addresses and values )'''
    from haystack import abouchet
    import ctypes, sslsnoop
    instances = abouchet.searchIn(structType='sslsnoop.ctypes_openssh.session_state', mappings=self.mappings, maxNum=999)
    if len(instances) > 0:
      log.debug('received %d struct of size %d'%(len(instances),len(instances[0][0])))
    # init graphical element
    self.sessionStateList = QtGui.QGraphicsItemGroup()
    for value, addr in instances:
      offset = addr - self.mapping.start
      self.sessionStateList.addToGroup(widgets.Structure( offset, value, color=QtCore.Qt.green, scene=self.scene))
    # fill the scene
    self.scene.addItem(self.sessionStateList)
    #self.sessionStateList.hide()
    self.sessionStateList.setZValue(20) # zValue has to be  > 0
    log.debug('Found %d instances'%(len(instances)) )
    # TODO : set self.mappings in weakref ?
    return len(instances)


class MyMain(QtGui.QMainWindow, Ui_MainWindow):

  sessionStateList = None
  pointers = None
  nullWords = None
  def __init__(self, argv, parent=None):
    QtGui.QMainWindow.__init__(self, parent)
    # draw the window
    self.setupUi(self)
    # populate useful data
    self.setupUi2()
    #widgets.Structure( 2000, Dummy(12000), color=QtCore.Qt.green, scene=self.scene)
    self.argv = argv

  def setupUi2(self):        
    # regroup tabs in a dict
    self.memorydump_tabs = dict()
    # connect menu
    self.connect(self.menu_file_exit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
    self.connect(self.menu_file_open, QtCore.SIGNAL('triggered()'), self.openDump)
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
    
    tab = MemoryDumpWidget(dump_name)
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

  '''  
  def makeGui(self):
    shell = QtGui.QPushButton('Interactive', self)
    shell.setGeometry(10, 10, 60, 35)
    #self.connect(shell, QtCore.SIGNAL('clicked()'), QtGui.qApp, QtCore.SLOT(('dropToInteractive()'))    
    self.connect(shell, QtCore.SIGNAL('clicked()'), dropToInteractive)
  '''
  
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
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memdump')
  rootparser.add_argument('--lazy', action='store_const', const=True , help='Lazy load')
  rootparser.set_defaults(func=gui)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('widget').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
