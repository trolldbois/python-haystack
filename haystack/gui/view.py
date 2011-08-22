#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('view')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt

from .. import model

LINE_SIZE=512
PAGE_SIZE=4096 

#LINE_SIZE=512*4
#PAGE_SIZE=4096*16 

class MemoryMappingScene(QtGui.QGraphicsScene):
  ''' 
  Binds a Memory mapping to a QGraphicsScene 
  '''
  def __init__(self, mapping, parent=None):  
    QtGui.QGraphicsScene.__init__(self,parent)
    self.mapping = mapping

class MemoryMappingView(QtGui.QGraphicsView):
  '''
  We need to define our own QGraphicsView to play with.
  zoom-able QGraphicsView.
  
  from http://www.qtcentre.org/wiki/index.php?title=QGraphicsView:_Smooth_Panning_and_Zooming
  '''
  #Holds the current centerpoint for the view, used for panning and zooming
  CurrentCenterPoint = QtCore.QPointF()
  #From panning the view
  LastPanPoint = QtCore.QPoint()

  def __init__(self, parent=None):  
    QtGui.QGraphicsView.__init__(self,parent)    
    self.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.SmoothPixmapTransform)
    #opengl ? !
    ###self.setViewport(QtOpenGL.QGLWidget(QtOpenGL.QGLFormat(QtOpenGL.QGL.SampleBuffers)))
    #self.setCursor(Qt.OpenHandCursor)
    self.setCursor(Qt.ArrowCursor)
    self.SetCenter(QtCore.QPointF(0.0, 0.0)) #A modified version of centerOn(), handles special cases
    
  def loadMapping(self, mapping):
    #Set-up the scene
    scene =  MemoryMappingScene(mapping, parent=self)
    self.setScene(scene)
    self.mapping = mapping
    #Set-up the view
    if mapping :
      #Populate the scene
      #self._debugFill(scene)
      self.drawPages(mapping)
      self.setSceneRect(0, 0, LINE_SIZE, (len(mapping) // LINE_SIZE)+1)
      # draw a square around      
      self.scene().addRect(  0, 0, LINE_SIZE, (len(mapping) // LINE_SIZE)+1, QtGui.QPen(Qt.SolidLine))
      log.debug('set sceneRect to %d,%d'%(LINE_SIZE, (len(mapping) // LINE_SIZE)+1)) 
    else:
      self.setSceneRect(0, 0, LINE_SIZE, LINE_SIZE) 
    self.SetCenter(QtCore.QPointF(0.0, 0.0)) #A modified version of centerOn(), handles special cases
    return

  def drawPages(self, mapping ):
    ''' draw a page delimitor every PAGE_SIZE '''
    pageSize = PAGE_SIZE
    # 15 is the mapping's size//PAGE_SIZE
    for y in xrange(PAGE_SIZE//LINE_SIZE, (len(mapping)//LINE_SIZE)-1, PAGE_SIZE//LINE_SIZE):
      self.scene().addLine(0, y, LINE_SIZE, y, QtGui.QPen(Qt.DotLine))
    
  
  def _debugFill(self,scene):
    for x in xrange(0,LINE_SIZE,25):
      for y in xrange(0,LINE_SIZE,25):
        if (x % 100 == 0 )and ( y % 100 == 0):
          scene.addRect(x, y, 2, 2)
          pointString = QtCore.QString()
          stream = QtCore.QTextStream(pointString)
          stream << "(" << x << "," << y << ")"
          item = scene.addText(pointString)
          item.setPos(x, y)
        else:
          scene.addRect(x, y, 1, 1)
 
  def GetScene(self):
    return self.scene()
    
  def GetCenter(self):
    return self.CurrentCenterPoint
  '''
    * Sets the current centerpoint.  Also updates the scene's center point.
    * Unlike centerOn, which has no way of getting the floating point center
    * back, SetCenter() stores the center point.  It also handles the special
    * sidebar case.  This function will claim the centerPoint to sceneRec ie.
    * the centerPoint must be within the sceneRec.
  '''
  #Set the current centerpoint in the
  def SetCenter(self,centerPoint):
    #Get the rectangle of the visible area in scene coords
    visibleArea = self.mapToScene(self.rect()).boundingRect()
 
    #Get the scene area
    sceneBounds = self.sceneRect()
 
    boundX = visibleArea.width() / 2.0
    boundY = visibleArea.height() / 2.0
    boundWidth = sceneBounds.width() - 2.0 * boundX
    boundHeight = sceneBounds.height() - 2.0 * boundY
 
    #The max boundary that the centerPoint can be to
    bounds = QtCore.QRectF(boundX, boundY, boundWidth, boundHeight)
   
    if (bounds.contains(centerPoint)):
      #We are within the bounds
      self.CurrentCenterPoint = centerPoint
    else:
      #We need to clamp or use the center of the screen
      if(visibleArea.contains(sceneBounds)):
          #Use the center of scene ie. we can see the whole scene
          self.CurrentCenterPoint = sceneBounds.center()
      else:
          self.CurrentCenterPoint = centerPoint
          #We need to clamp the center. The centerPoint is too large
          if(centerPoint.x() > bounds.x() + bounds.width()):
            self.CurrentCenterPoint.setX(bounds.x() + bounds.width())
          elif (centerPoint.x() < bounds.x()):
            self.CurrentCenterPoint.setX(bounds.x())

          if(centerPoint.y() > bounds.y() + bounds.height()):
            self.CurrentCenterPoint.setY(bounds.y() + bounds.height())
          elif (centerPoint.y() < bounds.y()) :
            self.CurrentCenterPoint.setY(bounds.y())
 
    #Update the scrollbars
    self.centerOn(self.CurrentCenterPoint)
    return
 
  '''
    * Handles when the mouse button is pressed
  '''
  def mousePressEvent(self, event):
    ''' todo 
    wierd, quand pointers et nullwords sont affiches, on ne peut plus selecter le pointer..
    ca tombe sur l'itemgroup des null words.
    '''
    #For panning the view
    self.LastPanPoint = event.pos()
    self.setCursor(Qt.ClosedHandCursor)
    item = self.itemAt(event.pos())
    log.debug('Mouse press on '+str(item))
    if item is None:
      return
    item.setSelected(True)
    pitem = item.parentItem()
    if pitem is None:
      # no parent item, that must be lonely....
      if self.mapping :
        # read mapping value 
        addr = event.pos().y()* LINE_SIZE + event.pos().x()
        value = self.mapping.readWord(self.mapping.start+addr)
        log.debug('@0x%x: 0x%x'%(self.mapping.start+addr,value))      
    else:
      # parent item, check for haystack types
      log.debug('Mouse press on parent item '+str(pitem))
      if hasattr(pitem,'value') and model.isRegistered(pitem.value):
        log.debug('showing info for %s'%(pitem))
        # update info view
        self.parent().showInfo(pitem)
      elif hasattr(pitem, 'onSelect' ):
        # print status for pointers and nulls
        log.debug('running parent onSelect')
        pitem.onSelect()
      elif hasattr(item, 'onSelect' ):
        log.debug('running item onSelect')
        pitem.onSelect()
      else:
        log.debug('%s has no onSelect method'%item)
      
    return
 
  '''
    * Handles when the mouse button is released
  '''
  def mouseReleaseEvent(self,event):
    #self.setCursor(Qt.OpenHandCursor)
    self.setCursor(Qt.ArrowCursor)
    self.LastPanPoint = QtCore.QPoint()
    return
 
  '''
  *Handles the mouse move event
  '''
  def mouseMoveEvent(self, event):
    if ( not self.LastPanPoint.isNull()):
        #Get how much we panned
        delta = self.mapToScene(self.LastPanPoint) - self.mapToScene(event.pos())
        self.LastPanPoint = event.pos()
 
        #Update the center ie. do the pan
        self.SetCenter(self.GetCenter() + delta)
    return 

  '''
  * Zoom the view in and out.
  '''
  def wheelEvent(self, event):
    #Get the position of the mouse before scaling, in scene coords
    pointBeforeScale = QtCore.QPointF(self.mapToScene(event.pos()))

    #Get the original screen centerpoint
    screenCenter = self.GetCenter() #CurrentCenterPoint; //(visRect.center());

    #Scale the view ie. do the zoom
    scaleFactor = 1.15; #How fast we zoom
    if(event.delta() > 0):
      #Zoom in
      self.scale(scaleFactor, scaleFactor)
    else :
      #Zooming out
      self.scale(1.0 / scaleFactor, 1.0 / scaleFactor)

    #Get the position after scaling, in scene coords
    pointAfterScale = QtCore.QPointF(self.mapToScene(event.pos()))

    #Get the offset of how the screen moved
    offset = pointBeforeScale - pointAfterScale

    #Adjust to the new center for correct zooming
    newCenter = screenCenter + offset
    self.SetCenter(newCenter) # QPointF
    return
 
  '''
    * Need to update the center so there is no jolt in the
    * interaction after resizing the widget.
  '''
  def resizeEvent(self, event):
    #Get the rectangle of the visible area in scene coords
    visibleArea = self.mapToScene(self.rect()).boundingRect()
    self.SetCenter(visibleArea.center())
 
    #Call the subclass resize so the scrollbars are updated correctly
    super(QtGui.QGraphicsView,self).resizeEvent(event)
    return     
    
    
