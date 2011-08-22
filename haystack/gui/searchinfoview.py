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
from .. import utils

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class SearchInfoView(QtGui.QWidget, Ui_SearchInfoStructWidget):
  '''
    this is the info view that is added to the right vertical tabView.
    It list resultset, and if the result set is a haystack C structure, a tableView is added underneath for more info.
  '''
  def __init__(self, graphicsScene, color, withDetails=False, parent=None):
    QtGui.QWidget.__init__(self, parent)
    # model
    self.graphicsScene = graphicsScene
    self.gitemgroup = QtGui.QGraphicsItemGroup(scene=self.graphicsScene)
    self.gitemgroup.setZValue(20) # zValue has to be  > 0
    self.color = color
    self.showDetailledView = withDetails
    self._init()

  def _init(self):
    self.initData()
    self.setupUi()
    self.setupSignals()

  def initData(self):
    self.results = []
    pass
        
  def setupUi(self):
    #setupUi()
    super(SearchInfoView,self).setupUi(self)
    # ours
    #self.setObjectName(_fromUtf8('resultset'))
    # delete splitter ?
    #self.info_tableview.setParent(None)
    #del self.info_tableview
    ## init table view
    if self.showDetailledView:
      self._addInfoTable() #must be called before initListView
      #self._showInfo(self, self.resultSet[0])
    
    ## init list view
    header = [_fromUtf8("Matches")] # translate
    self.list_model = infomodel.ResultListModel([], header, self.info_listview) 
    self.info_listview.setModel(self.list_model)
    # set the font
    font = QtGui.QFont("Courier New", 8)
    self.info_listview.setFont(font)
      
    return
  

  def _addInfoTable(self):
    self.info_tableview = QtGui.QTableView(self)
    self.info_tableview.setObjectName(_fromUtf8("%s_info_tableview"%(self)))
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
    self.splitter.setObjectName(_fromUtf8("%s_splitter_search_info"%(self)))
    self.gridLayout.addWidget(self.splitter, 0, 0, 1, 2)    
  
  def setupSignals(self):
    #for each tab
    # signals - connect higlighting options
    #QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL(_fromUtf8("activated(QModelIndex)")), self.info_listview.update)
    QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL("clicked(QModelIndex)"), self.listview_clicked)    
    #QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL("doubleClicked(QModelIndex)"), self.listview_dclicked)    
    QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL("activated(QModelIndex)"), self.listview_activated)    
    #QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL("selectionChanged(QModelSelection)"), self.listview_activated)    

    QtCore.QObject.connect(self.info_tableview, QtCore.SIGNAL("clicked(QModelIndex)"), self.tableview_clicked)    
    pass
  
  def addResult(self, offset, value, color=None):
    ''' creates a structure in the graphics scene. 
    adds the structure in the resultset group.
    adds the value to the table list.
    
    change color or use default color for the searchinfoview
    '''
    if color is None:
      color = self.color
    it = widgets.Structure( offset, value, color=color, scene=self.graphicsScene)
    self.gitemgroup.addToGroup(it)
    self.list_model.insertRows([str(value)]) # inserting text
    self.results.append(it)
    return
  
  def _showInfo(self, structure):
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
   
  def listview_activated (self, qindex):
    log.info('activated %d'%qindex.row())

  def listview_clicked (self, qindex):
    log.info('clicked %d'%qindex.row())
    item = self.list_model.data(qindex, Qt.DisplayRole)
    log.info('clicked %s'%(item))
    if self.showDetailledView:
      self._showInfo(self.results[qindex.row()])
    ### change the hexview
    # c'est le fun
    hexedit = self.parent().parent().parent().parent().parent().qhexedit
    structure = self.results[qindex.row()]
    hexedit.scrollTo(structure.offset)
    hexedit.setSelected(structure.offset, len(structure.value) )
    return

  def selectionChanged(self, new, old ):
    log.debug('selection changed')

  def tableview_clicked (self, qindex):
    log.info('clicked %d'%qindex.row())
    #item = self.info_tableview.model().data(qindex , Qt.DisplayRole)
    name,value = self.info_tableview.model().arraydata[qindex.row()]
    ### change the hexview
    #utils.offsetof(name,)
    #self.parent().parent().parent().parent().parent().qhexedit.setSelectedscrollTo(val.offset)
    return






