import logging
import argparse, os, pickle, time, sys

from .. import memory_dumper
from .. import memory_mapping
#from ..memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

import view


class MyWidget(QtGui.QMainWindow):
  sessionStateList = None
  pointers = None
  nullWords = None
  def __init__(self, mappings, parent=None):
    QtGui.QMainWindow.__init__(self, parent)
    self.mappings = mappings
    self.initUI()
    self.initModel()
    self.loadMapping(self.heap)

  def initUI(self):        
    self.widgets = dict()
    self.setGeometry(400, 100, 800, 600)
    #self.resize(800, 600)
    self.setWindowTitle('memory analysis')
    #self.setWindowIcon(QtGui.QIcon('icons/web.png'))
    exit = QtGui.QAction(QtGui.QIcon('icons/exit.png'), 'Exit', self)
    exit.setShortcut('Ctrl+Q')
    exit.setStatusTip('Exit application')
    self.connect(exit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
    self.statusBar()
    menubar = self.menuBar()
    file = menubar.addMenu('&File')
    file.addAction(exit)
            
    #self.view = view.View(self.scene,self)
    self.view = view.View(self)
    self.view.resize(512,620)
    self.view.show()  
    self.scene = self.view.GetScene()
    rect = self.scene.addRect(QtCore.QRectF(0, 0, view.LINE_SIZE, view.LINE_SIZE), QtCore.Qt.black)
    self.initLeftSide()
    
      
  def initLeftSide(self):
    cb = QtGui.QCheckBox('Show possible pointers', self)
    cb.setFocusPolicy(QtCore.Qt.NoFocus)
    cb.move(550, 10)
    cb.resize(200,20)
    self.connect(cb, QtCore.SIGNAL('stateChanged(int)'), 
        self._checkPointers)
    cb2 = QtGui.QCheckBox('Show null words', self)
    cb2.setFocusPolicy(QtCore.Qt.NoFocus)
    cb2.move(550, 50)
    cb2.resize(200,20)
    self.connect(cb2, QtCore.SIGNAL('stateChanged(int)'), 
        self._checkNulls)
    # search session_state button        
    search = QtGui.QCheckBox('Search session_state', self)
    search.setFocusPolicy(QtCore.Qt.NoFocus)
    search.setGeometry(550, 90, 160, 35)
    self.connect(search, QtCore.SIGNAL('stateChanged(int)'), self.showSessionState)
        
        
    self.widgets['checkPointers'] = cb
    self.widgets['checkNulls'] = cb2
    self.widgets['session_state'] = search

  def initModel(self):
    self.heap = [m for m in self.mappings if m.pathname == '[heap]'][0]
    self.pointers = None
    self.nullWords = None
  

  def makeGui(self):
    shell = QtGui.QPushButton('Interactive', self)
    shell.setGeometry(10, 10, 60, 35)
    #self.connect(shell, QtCore.SIGNAL('clicked()'), QtGui.qApp, QtCore.SLOT(('dropToInteractive()'))    
    self.connect(shell, QtCore.SIGNAL('clicked()'), dropToInteractive)

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

  def _checkPointers(self):
    if not self.widgets['checkPointers'].checkState():
      self.pointers.hide()
    else:
      self.pointers.show()
    
  def _checkNulls(self):
    if not self.widgets['checkNulls'].checkState():
      self.nullWords.hide()
    else:
      self.nullWords.show()
    
  def _makeStruct(self,offset,size):
    ''' fix line length to 4K '''
    width = 512 # use PAGE_SIZE ?
    words = set()
    x1 = (offset % width )
    y = (offset // width )
    for add in xrange(1,size):
      x2 = ((offset+add) % width )
      if x2 < x1: # goto next line
        words.add(QtCore.QRectF(x1, y, width-x1, 1)) # finish line
        x1 = x2
        y = (offset+add) // width 
        y = y+1          
    y = ((offset+add) // width)
    words.add(QtCore.QRectF(x1, y, x2-x1, 1 ) )
    return words

  def loadMapping(self, mmaping):
    log.debug('parsing heap mapping')
    self.pointers = QtGui.QGraphicsItemGroup()
    self.nullWords = QtGui.QGraphicsItemGroup()
    found = 0 
    nb = self.heap.end - self.heap.start    
    for offset in xrange(0,nb,4):
      i = offset + self.heap.start
      word = self.heap.readWord(i)
      # find pointers
      if word in self.heap:
        found +=1
        for l in self._makeStruct(offset,4):
          self.pointers.addToGroup(self.scene.addRect(l, QtCore.Qt.red))
      elif word == 0: # find null values
        for l in self._makeStruct(offset,4):
          self.nullWords.addToGroup(self.scene.addRect(l, QtCore.Qt.gray))
    # fill the scene
    self.scene.addItem(self.pointers)
    self.scene.addItem(self.nullWords)
    self.pointers.hide()
    self.nullWords.hide()
    return

  def showSessionState(self):
    if self.sessionStateList is None:
      self.searchSessionState()
    if not self.widgets['session_state'].checkState():
      self.sessionStateList.hide()
    else:
      self.sessionStateList.show()
    

  def searchSessionState(self):
    ''' return size of structure and list off addresses and values )'''
    from haystack import abouchet
    import ctypes, sslsnoop
    import sslsnoop.ctypes_openssh
    instances = abouchet.searchIn(structType='sslsnoop.ctypes_openssh.session_state', mappings=self.mappings, maxNum=999)
    size = ctypes.sizeof(sslsnoop.ctypes_openssh.session_state)
    # init graphical element
    self.sessionStateList = QtGui.QGraphicsItemGroup()
    for value, addr in instances:
      offset = addr - self.heap.start
      for l in self._makeStruct(offset,size):
        self.sessionStateList.addToGroup(self.scene.addRect(l, QtCore.Qt.green))
    # fill the scene
    self.scene.addItem(self.sessionStateList)
    self.sessionStateList.hide()
    log.debug('Found %d instances'%(len(instances)) )
    return len(instances)

def dropToInteractive():
  import code
  code.interact(local=locals())

              
def gui(opt):
  app = QtGui.QApplication(sys.argv)

  mappings = memory_dumper.load(opt)
  root = MyWidget(mappings)
  root.show()

  sys.exit(app.exec_())

def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-gui', description='Graphical tool.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memdump')
  rootparser.set_defaults(func=gui)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.getLogger('haystack').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
