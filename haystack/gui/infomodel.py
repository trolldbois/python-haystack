#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging
import operator

log = logging.getLogger('infomodel')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt


 
class StructureInfoTableModel(QtCore.QAbstractTableModel): 
  def __init__(self, datain, headerdata, parent=None, *args): 
    """ datain: a list of lists
        headerdata: a list of strings
    """
    QtCore.QAbstractTableModel.__init__(self, parent, *args) 
    self.arraydata = datain
    self.headerdata = headerdata

  def rowCount(self, parent): 
    return len(self.arraydata) 

  def columnCount(self, parent): 
    return len(self.arraydata[0]) 

  def data(self, index, role): 
    if not index.isValid(): 
      return QtCore.QVariant() 
    elif role != Qt.DisplayRole: 
      return QtCore.QVariant() 
    return QtCore.QVariant(self.arraydata[index.row()][index.column()]) 

  def headerData(self, col, orientation, role):
    if orientation == Qt.Horizontal and role == Qt.DisplayRole:
      return QtCore.QVariant(self.headerdata[col])
    return QtCore.QVariant()

  def sort(self, Ncol, order):
    """Sort table by given column number.
    """
    self.emit(QtCore.SIGNAL("layoutAboutToBeChanged()"))
    self.arraydata = sorted(self.arraydata, key=operator.itemgetter(Ncol))        
    if order == Qt.DescendingOrder:
        self.arraydata.reverse()
    self.emit(QtCore.SIGNAL("layoutChanged()"))
    


class ResultListModel(QtCore.QAbstractListModel): 
  def __init__(self, datain, headerdata, parent=None, *args): 
    """ 
    rowCount() and data() functions. Well behaved models also provide a headerData() 

    datain: a list of lists
    headerdata: a list of strings
    """
    QtCore.QAbstractListModel.__init__(self, parent, *args) 
    self.parent = parent
    self.arraydata = datain
    self.headerdata = headerdata

  def rowCount(self, parent):
    return len(self.arraydata) 

  def data(self, index, role): 
    if not index.isValid(): 
      return QtCore.QVariant() 
    elif role != Qt.DisplayRole: 
      return QtCore.QVariant() 
    return QtCore.QVariant(self.arraydata[index.row()]) 

  def insertRows(self, rows):
    index = len(self.arraydata)
    nb = len(rows)
    self.beginInsertRows(self.index(0), index, nb)
    self.arraydata.extend(rows)
    self.endInsertRows()


  def columnCount(self, parent): 
    return len(self.arraydata[0]) 


  def headerData(self, col, orientation, role):
    if orientation == Qt.Horizontal and role == Qt.DisplayRole:
      return QtCore.QVariant(self.headerdata[col])
    return QtCore.QVariant()

  def sort(self, Ncol, order):
    """Sort table by given column number.
    """
    self.emit(QtCore.SIGNAL("layoutAboutToBeChanged()"))
    self.arraydata = sorted(self.arraydata, key=operator.itemgetter(Ncol))        
    if order == Qt.DescendingOrder:
        self.arraydata.reverse()
    self.emit(QtCore.SIGNAL("layoutChanged()"))



