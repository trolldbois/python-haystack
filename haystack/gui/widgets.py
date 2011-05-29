
import logging

log = logging.getLogger('view')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt


class Structure(QtGui.QGraphicsItemGroup):
  '''
    Represente une structure dans notre MemoryScene.
  '''
  def __init__(self, offset, loadable, color = QtCore.Qt.green, scene=None, parent=None):
    QtGui.QGraphicsItemGroup.__init__(self, parent, scene)
    self.scene = scene
    self.struct = loadable
    self.offset = offset
    self.color = color
    self._makeStruct(self.offset, len(self.struct))
  
  def _makeStruct(self, offset, size):
    ''' fix line length to 4K '''
    width = 512 # use PAGE_SIZE ?
    x1 = (offset % width )
    y = (offset // width )
    for add in xrange(1,size):
      x2 = ((offset+add) % width )
      if x2 < x1: # goto next line
        # finish line
        self.addToGroup(self.scene.addRect(QtCore.QRectF(x1, y, width-x1, 1), self.color))
        x1 = x2
        y = (offset+add) // width 
        y = y+1          
    y = ((offset+add) // width)
    self.addToGroup(self.scene.addRect(QtCore.QRectF(x1, y, x2-x1, 1), self.color))
    return

