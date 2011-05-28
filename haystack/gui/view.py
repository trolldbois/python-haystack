

import logging

log = logging.getLogger('view')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt

 

class View(QtGui.QGraphicsView):
  #Holds the current centerpoint for the view, used for panning and zooming
  CurrentCenterPoint = QtCore.QPointF()
  #From panning the view
  LastPanPoint = QtCore.QPoint()

  '''
  zoom-able view.
  from http://www.qtcentre.org/wiki/index.php?title=QGraphicsView:_Smooth_Panning_and_Zooming
  '''
  def __init__(self, parent=None):  
    QtGui.QGraphicsView.__init__(self,parent)
    self.setRenderHints(QtGui.QPainter.Antialiasing | QtGui.QPainter.SmoothPixmapTransform)
 
    #Set-up the scene
    scene =  QtGui.QGraphicsScene(self)
    self.setScene(scene)
    self.scene = scene
 
    #Populate the scene
    for x in xrange(0,1000,25):
      for y in xrange(0,1000,25):
        if (x % 100 == 0 )and ( y % 100 == 0):
          scene.addRect(x, y, 2, 2)
          pointString = QtCore.QString()
          stream = QtCore.QTextStream(pointString)
          stream << "(" << x << "," << y << ")"
          item = scene.addText(pointString)
          item.setPos(x, y)
        else:
          scene.addRect(x, y, 1, 1)
 
    #Set-up the view
    self.setSceneRect(0, 0, 1000, 1000)
    self.SetCenter(QtCore.QPointF(500.0, 500.0)) #A modified version of centerOn(), handles special cases
    self.setCursor(Qt.OpenHandCursor)
    return

  def GetScene(self):
    return self.scene
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
    #For panning the view
    self.LastPanPoint = event.pos()
    self.setCursor(Qt.ClosedHandCursor)
    return
 
  '''
    * Handles when the mouse button is released
  '''
  def mouseReleaseEvent(self,event):
    self.setCursor(Qt.OpenHandCursor)
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
    
    
