import logging
import argparse, os, pickle, time, sys

from .. import memory_dumper
from .. import memory_mapping
#from ..memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

import view


class MyWidget(QtGui.QMainWindow):
  def __init__(self, mappings, parent=None):
    QtGui.QMainWindow.__init__(self, parent)
    self.mappings = mappings
    self.initUI()
    self.initModel()
    self.loadMapping(self.heap)

  def initUI(self):        
    self.widgets = dict()
    self.setGeometry(100, 100, 800, 600)
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
            
    self.scene = QtGui.QGraphicsScene(self)
    rect = self.scene.addRect(QtCore.QRectF(0, 0, 500, 500), QtCore.Qt.black)
    #self.view = view.View(self.scene,self)
    self.view = view.View(self)
    self.view.resize(500,620)
    self.view.show()  
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
    self.widgets['checkPointers'] = cb
    self.widgets['checkNulls'] = cb2

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
    
  def _makeQLineWord(self,offset):
    lines = set()
    size = self.view.size()    
    x1 = (offset % size.width() )
    y1 = (offset // size.height())
    for add in [1,2,3,4]:
      x2 = 1+ ((offset+add) % size.width() )
      if x2 < x1: # goto next line
        lines.add(QtCore.QLineF(x1, y1, size.width(), y1))
        x1 = x2
        y1 = y1+1          
      y2 = ((offset+add) // size.height())
    lines.add(QtCore.QLineF(x1, y1, x2, y2 ) )
    return lines

  def loadMapping(self, mmaping):
    log.debug('parsing heap mapping')
    self.pointers = QtGui.QGraphicsItemGroup()
    self.nullWords = QtGui.QGraphicsItemGroup()
    found = 0 
    nb = self.heap.end - self.heap.start    
    for offset in xrange(0,nb,4):
      i = offset + self.heap.start
      word = self.heap.readWord(i)
      if word in self.heap:
        found +=1
        for l in self._makeQLineWord(offset):
          self.pointers.addToGroup(self.scene.addLine(l, QtCore.Qt.red))
      elif word == 0:
        for l in self._makeQLineWord(offset):
          self.nullWords.addToGroup(self.scene.addLine(l, QtCore.Qt.gray))
    # fill the scene
    self.scene.addItem(self.pointers)
    self.scene.addItem(self.nullWords)
    self.pointers.hide()
    self.nullWords.hide()
    return

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
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
