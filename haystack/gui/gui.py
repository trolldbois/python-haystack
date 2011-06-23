import logging
import argparse, os, pickle, time, sys

from .. import memory_dumper
from .. import memory_mapping
#from ..memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

import view
import widgets


class Dummy:
  def __init__(self,len_):
    self._len_= len_
  def __len__(self):
    return self._len_

class MyWidget(QtGui.QMainWindow):
  sessionStateList = None
  pointers = None
  nullWords = None
  def __init__(self, argv, parent=None):
    QtGui.QMainWindow.__init__(self, parent)
    self.initUI()
    widgets.Structure( 2000, Dummy(12000), color=QtCore.Qt.green, scene=self.scene)
    self.argv = argv

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
    # open memdump
    openDump = QtGui.QAction(QtGui.QIcon('icons/open.png'), 'Open...', self)
    openDump.setShortcut('Ctrl+O')
    openDump.setStatusTip('Open...')
    self.connect(openDump, QtCore.SIGNAL('triggered()'), self.openDump)
    #
    self.statusBar()
    menubar = self.menuBar()
    file = menubar.addMenu('&File')
    file.addAction(openDump)
    file.addAction(exit)
            
    self.view = view.MemoryMappingView(mapping = None, parent = self)
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
    mappings = memory_dumper.load(self.argv)
    self.mappings = mappings
    self.heap = [m for m in self.mappings if m.pathname == '[heap]'][0]
    self.pointers = None
    self.nullWords = None
    #reinit the view
    self.view.hide()  
    self.view = view.MemoryMappingView(mapping = self.heap, parent = self)
    self.view.resize(520, 620)
    #self.view.resize(view.LINE_SIZE, (len(self.heap) // view.LINE_SIZE)+1 )
    self.view.show()  
    self.scene = self.view.GetScene()
  
  def openDump(self):
    # load memorymapping
    self.initModel()
    self.loadMapping(self.heap)
    pass
  
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
        self.pointers.addToGroup(widgets.Word(offset,word,scene = self.scene, color = QtCore.Qt.red) )
      elif word == 0: # find null values
        self.nullWords.addToGroup(widgets.Word(offset,word,scene = self.scene, color = QtCore.Qt.gray) )
    # fill the scene
    self.scene.addItem(self.pointers)
    self.scene.addItem(self.nullWords)
    self.pointers.hide()
    self.pointers.setFlag(QtGui.QGraphicsItem.ItemIsSelectable, False)
    self.nullWords.hide()
    self.nullWords.setEnabled(False)
    # still not letting me trough the boundingRect
    self.nullWords.setToolTip('Null value words')
    log.debug(self.pointers)
    log.debug(self.nullWords)
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
    instances = abouchet.searchIn(structType='sslsnoop.ctypes_openssh.session_state', mappings=self.mappings, maxNum=999)
    if len(instances) > 0:
      log.debug('received %d struct of size %d'%(len(instances),len(instances[0][0])))
    # init graphical element
    self.sessionStateList = QtGui.QGraphicsItemGroup()
    for value, addr in instances:
      offset = addr - self.heap.start
      self.sessionStateList.addToGroup(widgets.Structure( offset, value, color=QtCore.Qt.green, scene=self.scene))
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

  #mappings = memory_dumper.load(opt)
  mappings = None
  root = MyWidget(opt)
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
