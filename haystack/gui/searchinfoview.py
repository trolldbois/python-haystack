#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('searchinfoview')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt

from searchinfoStruct import Ui_SearchInfoStructWidget
import infomodel
import widgets

# IMPORTANT: we need to keep the module hierarchy, otherwise the book register/singleton is dead
from haystack import model 

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class SearchInfoView(QtGui.QWidget, Ui_SearchInfoStructWidget):
  '''
    this is the info view that is added to the right vertical tabView.
    It list resultset, and if the result set is a haystack C structure, a tableView is added underneath for more info.
  '''
  def __init__(self, graphicsScene, resultSet=[], parent=None):
    QtGui.QWidget.__init__(self, parent)
    # model
    self.graphicsScene = graphicsScene
    self.gitemgroup = QtGui.QGraphicsItemGroup(scene=self.graphicsScene)
    self.gitemgroup.setZValue(20) # zValue has to be  > 0
    self.resultSet = resultSet
    self._init()

  def _init(self):
    self.initData()
    self.setupUi()
    self.setupSignals()
    self.initListView()

  def initData(self):
    pass
        
  def setupUi(self):
    #setupUi()
    super(SearchInfoView,self).setupUi(self)
    # ours
    #self.setObjectName(_fromUtf8('resultset'))
    # delete splitter ?
    self.info_tableview.setParent(None)
    del self.info_tableview
        
    # add table view
    self.refreshTableView()
  
  def refreshTableView(self):
    if len(self.resultSet) > 0 and  model.isRegistered(type(self.resultSet[0])):
      print 'showinfo'
      if not hasattr(self, 'info_tableview'):
        self._addInfoTable()
      #self.info_listView.setSelected(0)
      self._showInfo(self, self.resultSet[0])
    
  def setupSignals(self):
    #for each tab
    # signals - connect higlighting options
    pass
  
  def addResult(self, offset, value, color):
    it = widgets.Structure( offset, value, color=color, scene=self.graphicsScene)
    self.gitemgroup.addToGroup(it)
    self.list_model.insertRows([str(value)])
    self.refreshTableView()
    return
  
  def initListView(self):
    results = self.resultSet
    header = ['Matches'] # translate
    self.list_model = infomodel.ResultListModel(results, header, self.info_listview) 
    self.info_listview.setModel(self.list_model)
    # set the font
    font = QtGui.QFont("Courier New", 8)
    self.info_listview.setFont(font)
    # set horizontal header properties
    #hh = self.info_listview.horizontalHeader()
    #hh.setStretchLastSection(True)
    # set column width to fit contents
    #self.info_listview.resizeColumnsToContents()
    # set row height
    #nrows = self.list_model.rowCount(self.list_model)
    #for row in xrange(nrows):
    #    self.info_listview.setRowHeight(row, 18)
    # enable sorting
    #self.info_listview.setSortingEnabled(True)
    pass

  def _addInfoTable(self):
    self.info_tableview = QtGui.QTableView(self)
    self.info_tableview.setObjectName(_fromUtf8("info_tableview"))
    #self.gridLayout.addWidget(self.info_tableview, 2, 0, 1, 1)
    # add QSplitter
    self.splitter = QtGui.QSplitter(Qt.Vertical, self)
    self.splitter.addWidget(self.info_listview)
    self.splitter.addWidget(self.info_tableview)
    sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
    sizePolicy.setHorizontalStretch(0)
    sizePolicy.setVerticalStretch(0)
    sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
    self.splitter.setSizePolicy(sizePolicy) # resize
    self.splitter.setObjectName(_fromUtf8("splitter_search_info"))
    self.gridLayout.addWidget(self.splitter, 0, 0, 1, 2)    
  
  
  def _showInfo(self, structure):
    if not hasattr(self, 'info_tableview'):
      self._addInfoTable()
    log.info('show info on %s'%(structure))
    pyObj = structure.value
    rows = [ (k,str(v)) for k,v,typ in pyObj]
    log.debug('self.info_tableview populated with %d rows'%(len(rows)))    
    # set the table model
    header = ['field', 'value']
    tm = infomodel.StructureInfoTableModel(rows, header, self) 
    self.info_tableview.setModel(tm)
    # set the font
    font = QtGui.QFont("Courier New", 8)
    self.info_tableview.setFont(font)
    # hide vertical header
    vh = self.info_tableview.verticalHeader()
    vh.setVisible(False)
    # set horizontal header properties
    hh = self.info_tableview.horizontalHeader()
    hh.setStretchLastSection(True)
    # set column width to fit contents
    self.info_tableview.resizeColumnsToContents()
    # set row height
    nrows = len(rows)
    for row in xrange(nrows):
        self.info_tableview.setRowHeight(row, 18)
    # enable sorting
    self.info_tableview.setSortingEnabled(True)
    return
    
   
