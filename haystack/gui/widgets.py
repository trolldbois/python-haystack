
import logging

log = logging.getLogger('view')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt

import view

class Structure(QtGui.QGraphicsItemGroup):
  '''
    Represente une structure dans notre MemoryScene.
    QGraphicsItem::ItemIsSelectable
  '''
  def __init__(self, offset, loadable, color = QtCore.Qt.green, scene=None, parent=None):
    QtGui.QGraphicsItemGroup.__init__(self, parent, scene)
    self.scene = scene
    self.struct = loadable
    self.offset = offset
    self.color = color
    log.debug('size: %d'%len(self.struct))
    self._makeStruct(self.offset, len(self.struct))
    log.debug('hover: %s handleChildEvents: %s'%( self.acceptsHoverEvents(), self.handlesChildEvents()) )
    self.setAcceptsHoverEvents(True)
    self.setHandlesChildEvents(True)
    self.setFlags(QtGui.QGraphicsItem.ItemIsSelectable)
  
  def _makeStruct(self, offset, size):
    ''' fix line length to 4K '''
    width = 512 # use PAGE_SIZE ?
    x1 = (offset % width )
    y = (offset // width )
    # if offset+xoff > width, draw first line to the end.
    # else, draw the rect and quit
    if (x1 + size > width):
      self.addToGroup(self.scene.addRect(QtCore.QRectF(x1, y, width-x1, 1), self.color, QtGui.QBrush(self.color)))
      log.debug('line %d : %d,%d,%d,%d first'%(y, x1, y, width-x1, 1))
    else:
      self.addToGroup(self.scene.addRect(QtCore.QRectF(x1, y, size, 1), self.color, QtGui.QBrush(self.color)))
      #log.debug('line 1 : %d,%d,%d,%d stop'%(x1, y, size, 1))
      return
    # then draw big rect full lines from ya = y+1  to yb = ((offset+size) // width) - 1
    yf = ((offset+size) // width)
    if ( yf > y+1 ):
      for ya in xrange(y+1, yf):
        self.addToGroup(self.scene.addRect(QtCore.QRectF(0, ya, width, 1), self.color, QtGui.QBrush(self.color)))
        log.debug('line %d : %d,%d,%d,%d'%(ya, 0, ya, width, 1))
    # then draw last line from x = 0 to x = offset+size // width
    xf = ((offset+size) % width )
    self.addToGroup(self.scene.addRect(QtCore.QRectF(0, yf, width-xf, 1), self.color, QtGui.QBrush(self.color)))
    log.debug('line %d : %d,%d,%d,%d stop'%(yf, 0, yf, width-xf, 1))
    return

  def __repr__(self):
    s=''
    if repr(self.struct) != '':
      s=": %s"%(repr(self.struct))
    return "<Structure of %d bytes%s>"%(len(self.struct),s)

class Word(Structure):
  ''' QtCore.QRectF is not a graphicsitem '''
  def __init__(self, offset, value, color = QtCore.Qt.yellow, scene=None, parent=None):
    QtGui.QGraphicsItemGroup.__init__(self, parent, scene)
    self.scene = scene
    self.value = value
    self.offset = offset
    self.color = color
    self._makeStruct(self.offset, 4)
    self.setAcceptsHoverEvents(True)
    self.setHandlesChildEvents(True)
    self.setFlags(QtGui.QGraphicsItem.ItemIsSelectable)

  def __repr__(self):
    if self.scene is None:
      addr = self.offset
    else:
      addr = self.scene.mapping.start + self.offset
    return "<Word %s @%s>"%(hex(self.value), hex(addr))

