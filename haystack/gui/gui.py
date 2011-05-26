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
    #self.makeExit()
    self.mappings = mappings
    self.heap = [m for m in mappings if m.pathname == '[heap]'][0]

  def makeExit(self):
    quit = QtGui.QPushButton('Close', self)
    quit.setGeometry(10, 10, 60, 35)

    self.connect(quit, QtCore.SIGNAL('clicked()'),
        QtGui.qApp, QtCore.SLOT('quit()'))

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
      if word in self.heap:
        found +=1
        #
        offset = (float(i - self.heap.start) / mx_offset) * mx
        
        x = offset % size.width()
        y = offset // size.height()
        if found % 100 == 0:
          log.debug( 'found %d possible pointers (last one at %s (%d,%d)'%(found, hex(i), x,y ) )
    
        #y = size.height() * ((word & 0xffff0000 ) >> 4 ) / 0xffff )
        #x = size.width()  * (word & 0x0000ffff )  / 0xffff)
        qp.drawPoint(x, y)     
              
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
