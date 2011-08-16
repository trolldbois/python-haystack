#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('widget')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt

import view

class Structure(QtGui.QGraphicsItemGroup):
  '''
    Represente une structure dans notre MemoryScene.
    QGraphicsItem::ItemIsSelectable
  '''
  def __init__(self, offset, value, color = QtCore.Qt.green, scene=None, parent=None):
    QtGui.QGraphicsItemGroup.__init__(self, parent, scene)
    self.scene = scene
    self.value = value # ctypes_py structure
    self.offset = offset
    self.color = color
    log.debug('size: %d'%len(self.value))
    self._makeStruct(self.offset, len(self.value))
    log.debug('hover: %s handleChildEvents: %s'%( self.acceptsHoverEvents(), self.handlesChildEvents()) )
    self.setAcceptsHoverEvents(True)
    self.setHandlesChildEvents(True)
    self.setFlags(QtGui.QGraphicsItem.ItemIsSelectable)
    self.setToolTip(str(type(value)))
  
  def _makeStruct(self, offset, size):
    ''' fix line length to 4K '''
    width = view.LINE_SIZE # use PAGE_SIZE ?
    x1 = (offset % width )
    y = (offset // width )
    pen = QtGui.QPen(self.color)
    brush = QtGui.QBrush(self.color, style=Qt.SolidPattern)
    # if offset+xoff > width, draw first line to the end.
    # else, draw the rect and quit
    if (x1 + size > width):
      #QGraphicsRectItem ( const QRectF & rect, QGraphicsItem * parent = 0 )
      #self.addToGroup(QtCore.QGraphicsRectItem(QtCore.QRectF(x1, y, width-x1, 1), self.color, QtGui.QBrush(self.color)))
      '''
        we should create a QRectF, use it in the QgraphicItem(rect, parent=self)
        ans use setData on items
      '''
      gi = self.scene.addRect(QtCore.QRectF(x1, y, width-x1, 1), pen, brush)
      # gi is graphics item
      gi.setAcceptsHoverEvents(True)
      self.addToGroup(gi)
      log.debug('line %d : %d,%d,%d,%d first'%(y, x1, y, width-x1, 1))
    else:
      gi = self.scene.addRect(QtCore.QRectF(x1, y, size, 1), pen, brush)
      gi.setAcceptsHoverEvents(True)
      self.addToGroup(gi)
      #log.debug('line 1 : %d,%d,%d,%d stop'%(x1, y, size, 1))
      return
    # then draw big rect full lines from ya = y+1  to yb = ((offset+size) // width) - 1
    yf = ((offset+size) // width)
    if ( yf > y+1 ):
      for ya in xrange(y+1, yf):
        gi = self.scene.addRect(QtCore.QRectF(0, ya, width, 1), pen, brush)
        gi.setAcceptsHoverEvents(True)
        self.addToGroup(gi)
        log.debug('line %d : %d,%d,%d,%d'%(ya, 0, ya, width, 1))
    # then draw last line from x = 0 to x = offset+size // width
    xf = ((offset+size) % width )
    gi = self.scene.addRect(QtCore.QRectF(0, yf, width-xf, 1), pen, brush)
    gi.setAcceptsHoverEvents(True)
    self.addToGroup(gi)
    log.debug('line %d : %d,%d,%d,%d stop'%(yf, 0, yf, width-xf, 1))
    return

  def onSelect(self):
    ''' draw a rectangle around the boucingRect '''
    log.debug('a structure %s'%(self.value))
    # self.parent().currentTab().showInfo() # blabla
    pass

  def hoverEnterEvent(self,event):
    log.debug('hoover enter')

  def __repr__(self):
    s=''
    if repr(self.value) != '':
      s=": %s"%(repr(self.value))
    return "<Structure of %d bytes%s>"%(len(self.value),s)

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

  def onSelect(self):
    ''' draw a rectangle around the boucingRect '''
    print 'onselect', self
    #print 'onselect', super(Structure,self).onSelect
    #super(Structure,self).onSelect(self)
    # read mapping value 
    #addr = event.pos().y()* LINE_SIZE + event.pos().x()
    #value = self.mapping.readWord(self.mapping.start+addr)
    #log.debug('@0x%x: 0x%x'%(self.mapping.start+addr,value))
    #log.debug('on select @0x%x: 0x%x'%(offset,value))
    #self.parent().showInfo(item)
    #addr = event.pos().y()* LINE_SIZE + event.pos().x()
    start = self.scene.mapping.start
    width = view.LINE_SIZE # use PAGE_SIZE ?
    x0 = (self.offset) % width 
    y0 = (self.offset) // width 
    x1 = (self.value-start) % width 
    y1 = (self.value-start) // width 
    self.scene.addLine(x0, y0, x1, y1)    
    print self.offset, x0, y0, x1, y1
    # todo ise a path
    pass

  def __repr__(self):
    if self.scene is None:
      addr = self.offset
    else:
      addr = self.scene.mapping.start + self.offset
    return "<Word (@0x%x) 0x%x>"%(addr, self.value)

