import logging
import argparse, os, pickle, time, sys

from haystack import memory_dumper
from haystack import memory_mapping
from haystack.memory_mapping import MemoryMapping


log = logging.getLogger('gui')

from PyQt4 import QtGui, QtCore

class MyWidget(QtGui.QWidget):
  def __init__(self, mapping, parent=None):
    QtGui.QWidget.__init__(self, parent)

    self.setGeometry(800, 600, 250, 150)
    self.setWindowTitle('memory analysis')
    #self.setWindowIcon(QtGui.QIcon('icons/web.png'))
    #self.makeExit()
    self.mapping = mapping

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
    
    for i in xrange(self.mapping.start,self.mapping.end,4):
      word = self.mapping.readWord(i)
      if word in self.mapping:
        print 'found a pointer value', hex(word)
        x = (word & 0xffff0000 ) >> 4
        y = (word & 0x0000ffff )
        qp.drawPoint(x, y)     
              
def gui(opt):
  app = QtGui.QApplication(sys.argv)

  memdump = memory_dumper.load(opt.dumpfile)
  root = MyWidget(memdump)
  root.show()

  sys.exit(app.exec_())

def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-gui', description='Graphical tool.')
  rootparser.add_argument('dumpfile', type=argparse.FileType('rb'), action='store', help='Source memdump')
  rootparser.set_defaults(func=gui)  
  return rootparser

def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
