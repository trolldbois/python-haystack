import logging
import argparse, os, pickle, time, sys

from .. import memory_dumper
from .. import memory_mapping
#from ..memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

class MyWidget(QtGui.QWidget):
  def __init__(self, mappings, parent=None):
    QtGui.QWidget.__init__(self, parent)

    self.setGeometry(100, 100, 800, 600)
    #self.resize(800, 600)
    self.setWindowTitle('memory analysis')
    #self.setWindowIcon(QtGui.QIcon('icons/web.png'))
    self.makeGui()
    self.mappings = mappings
    self.heap = [m for m in mappings if m.pathname == '[heap]'][0]

  def makeGui(self):
    shell = QtGui.QPushButton('Interactive', self)
    shell.setGeometry(10, 10, 60, 35)
    #self.connect(shell, QtCore.SIGNAL('clicked()'), QtGui.qApp, QtCore.SLOT(('dropToInteractive()'))    
    self.connect(shell, QtCore.SIGNAL('clicked()'), dropToInteractive)

  def closeEvent(self, event):
    reply = QtGui.QMessageBox.question(self, 'Message',
        "Are you sure to quit?", QtGui.QMessageBox.Yes | 
        QtGui.QMessageBox.No, QtGui.QMessageBox.No)

    if reply == QtGui.QMessageBox.Yes:
      event.accept()
    else:
      event.ignore()

  def paintEvent(self, event):
    qp = QtGui.QPainter()
    qp.begin(self)
    self.drawPointers(event, qp)
    qp.end()
    return

  def drawPointers(self, event, qp):
    #qp.setPen(QtGui.QColor(168, 34, 3))
    #qp.setFont(QtGui.QFont('Decorative', 10))
    #qp.drawText(event.rect(), QtCore.Qt.AlignCenter, self.text)
    qp.setPen(QtCore.Qt.red)
    log.debug('parsing heap mapping')
    size = self.size()
    # scale the offsets to the window
    mx = size.height() * size.width() 
    mx_offset = self.heap.end - self.heap.start
    found = 0 
    nb = self.heap.end - self.heap.start
    for off in xrange(0,nb,4):
      i = off + self.heap.start
      word = self.heap.readWord(i)
      #offset = (float(i - self.heap.start) / mx_offset) * mx
      offset = i - self.heap.start
      x = 1+ (offset % size.width() )
      y = 1+ (offset // size.height())
      if word in self.heap:
        found +=1
        qp.setPen(QtCore.Qt.red)
        #if found % 100 == 0:
        #  log.debug( 'found %d possible pointers (last one at %s (%d,%d)'%(found, hex(i), x,y ) )
      elif word == 0:
        qp.setPen(QtCore.Qt.black)
      # color the word
      qp.drawPoint(x, y)
      for add in [1,2,3]:
        x = 1+ add + (offset % size.width() )
        y = 1+ add + (offset // size.height())
        qp.drawPoint(x, y)
           
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
