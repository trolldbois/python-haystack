import logging
import argparse, os, pickle, time, sys

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
  def __init__(self,len_):
    self._len_= len_
  def __len__(self):
    return self._len_


class MemoryDumpWidget(QtGui.QWidget):
  def __init__(self, name):
    ''' from mainwindow.ui '''
    QtGui.QWidget.__init__(self)
    self.tab = self
    self.tab.setObjectName(_fromUtf8(name))
    self.gridLayout_3 = QtGui.QGridLayout(self.tab)
    self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
    self.graphicsView = QtGui.QGraphicsView(self.tab)
    self.graphicsView.setObjectName(_fromUtf8("graphicsView"))
    self.gridLayout_3.addWidget(self.graphicsView, 0, 0, 1, 1)
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
    self.show_search = QtGui.QCommandLinkButton(self.groupBox)
    self.show_search.setGeometry(QtCore.QRect(610, 0, 161, 36))
    self.show_search.setObjectName(_fromUtf8("show_search"))
    self.gridLayout_3.addWidget(self.groupBox, 1, 0, 1, 1)
    self.tabWidget.addTab(self.tab, _fromUtf8(""))
 

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
    widgets.Structure( 2000, Dummy(12000), color=QtCore.Qt.green, scene=self.scene)
    self.argv = argv

  def setupUi2(self):        
    # connect menu
    self.connect(self.menu_file_exit, QtCore.SIGNAL('triggered()'), QtCore.SLOT('close()'))
    self.connect(self.menu_file_open, QtCore.SIGNAL('triggered()'), self.openDump)
    # regroup tabs in a dict
    self.memorydump_tabs = dict()

  def make_memory_tab(self, dump_name):
    if dump_name in self.memorydump_tabs:
      # switch to tab
      #self.throw
      return
    
    tab = QtGui.QWidget()
    tab.setObjectName(_fromUtf8(dump_name))
    self.tabWidget.addTab(tab, _fromUtf8(os.path.basename(dump_name)))
    self.tabWidget.setCurrentIndex(self.tabWidget.count())
    self.memorydump_tabs[dump_name] = tab

    #for each tab
    # connect higlighting options
    self.connect(self.show_pointers, QtCore.SIGNAL('stateChanged(int)'), self._checkPointers)
    self.connect(self.show_null, QtCore.SIGNAL('stateChanged(int)'), self._checkNulls)
    self.connect(self.show_search, QtCore.SIGNAL('stateChanged(int)'), self.showSessionState)
      
    #self.graphicsView
    ''' = view.MemoryMappingView(mapping = None, parent = self)
    self.view.resize(512,620)
    '''
    #self.scene = self.view.GetScene()

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
  root = MyMain(opt)
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
