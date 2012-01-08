#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('searchview')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt
import inspect

from searchStruct import Ui_Search_Structure

from haystack import model
from haystack.reverse import signature
from haystack import utils

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__status__ = "Production"

class SearchStructDialog(QtGui.QDialog, Ui_Search_Structure):

  def __init__(self, parent=None):
    QtGui.QDialog.__init__(self, parent)
    # draw the window
    self.setupUi(self)
    self.setupSignals()
    self.setupData()
    return
  
  def setupUi(self,me):
    super(SearchStructDialog,self).setupUi(self)
    self.gridLayout.removeWidget(self.searchWidget_tree)
    self.gridLayout.addWidget(self.searchWidget_tree, 3, 0, 1, 2)
    self.setTabOrder(self.lineEdit_filter,self.searchWidget_tree)
    self.setTabOrder(self.searchWidget_tree,self.dialog_search_structure_buttonbox)
    self.lineEdit_filter.setFocus()
    #QTimer::singleShot(0, line, SLOT(setFocus());
    return
    
  def setupSignals(self):
    self.dialog_search_structure_buttonbox.accepted.connect(self.search)
    QtCore.QObject.connect(self.lineEdit_filter, QtCore.SIGNAL("textChanged(QString)"), self.filterTreeContent)
    QtCore.QObject.connect(self.searchWidget_tree, QtCore.SIGNAL("itemSelectionChanged()"), self.updateTreeSelection)
    QtCore.QObject.connect(self.searchWidget_tree, QtCore.SIGNAL("doubleClicked(QModelIndex)"), self.accept)
    QtCore.QObject.connect(self.searchWidget_tree, QtCore.SIGNAL("doubleClicked(QModelIndex)"), self.search)
    return
  
  def setupData(self):
    ''' init our state and fill our tree'''
    self.modules = set()
    self.classes = set()
    self.targetClassName = None
    self.fillTree()
    return
  
  def search(self):
    ''' triage between tabs '''
    currentTabIndex = self.tabWidget.currentIndex()
    if currentTabIndex == 0:
      self.search_struct()
    elif currentTabIndex == 1:
      self.search_regexp()
    elif currentTabIndex == 2:
      self.search_classics()
    else:
      log.warning('Did not known that tab : %d'%(currentTabIndex))
    return
    
  def search_struct(self):
    ''' get the current selection and launch the search on it'''
    # lock on target classe name
    targetClassName = self.selectedItem()
    if targetClassName is None:
      return
    log.debug('searching....')
    tab = self.parent().currentTab()
    if tab is not None:
      structs = tab.searchStructure(targetClassName)
      log.debug('The tab has found %d instances'%(len(structs)))
    return 
  
  def search_regexp(self):
    # -> search_regexp(self, regexp, searchName, color=QtCore.Qt.black):
    log.debug('Looking for a regexp r"%s" '%(self.lineEdit_regexp.text()) )
    tab = self.parent().currentTab()
    if tab is not None:
      items = tab.search_regexp(str(self.lineEdit_regexp.text()), str(self.lineEdit_regexp.text())[-20:])
      log.debug('The tab has found %d instances'%(len(items)))
    pass
    
  def search_classics(self):
    regs = dict([('email',signature.EmailRegexp),
    ('url',signature.URLRegexp),
    ('winfile',signature.WinFileRegexp),
    ('ipv4',signature.IPv4Regexp),
    ('ipv6',signature.IPv6Regexp),
    ('sql',signature.SQLRegexp),
    ('cc',signature.CCardRegexp),
    ('ssn',signature.SSNRegexp),
    ('guid',signature.GUIDRegexp),
    ])

    log.debug('Looking for a classic %s'%('aa') )
    tab = self.parent().currentTab()
    if tab is None:
      return
    #get select checkboxes
    import random
    colors=[#Qt.black, Qt.white, 
          Qt.gray, Qt.lightGray, 
          Qt.red, Qt.green, Qt.blue, Qt.cyan, Qt.magenta, Qt.yellow, 
          Qt.darkRed, Qt.darkGreen, Qt.darkBlue, Qt.darkCyan, Qt.darkMagenta, Qt.darkYellow]
    for choice in regs.keys():
      box, color = getattr(self, 'checkBox_%s'%(choice)), getattr(self, 'toolButton_%s'%(choice))
      ## DEBUG TODO
      color = random.randrange( len(colors) ) # pick the tooltip color picker color...
      if box.checkState():
        log.debug('%s %s %s'%(choice, box, colors[color]))
        tab.search_regexp( regs[choice], "Results for '%s' Regexp"%choice, colors[color] )
    # 
    
    pass
  
  def fillTree(self):
    # DEBUG 
    import sslsnoop.ctypes_openssh
    # we have to use haystack.model (.. .model) and not only model
    mods = model.registeredModules()
    log.debug('loading %d registered modules'%(len(mods)) )
    self.searchWidget_tree.setColumnCount(1)
    items = [ ]
    font = QtGui.QFont("Courier New", 8)
    for mod in mods:
      root = QtGui.QTreeWidgetItem([mod.__name__])
      it = None
      for cls,typ in inspect.getmembers(mod, inspect.isclass):
        fullname = '.'.join([mod.__name__,cls])      
        if typ.__module__.startswith(mod.__name__) and utils.isStructType(typ()):
          it = QtGui.QTreeWidgetItem(root, [cls] )
          it.setFont(0,font)
          self.classes.add(fullname)
      if it is not None:
        items.append(root)
        self.modules.add(mod)
    self.searchWidget_tree.insertTopLevelItems(0,items)
    return
  
  def filterTreeContent(self):
    txt = str(self.lineEdit_filter.text())
    items=[]
    font = QtGui.QFont("Courier New", 8)    
    for mod in self.modules:
      root = QtGui.QTreeWidgetItem([mod.__name__])
      it = None
      for cls,typ in inspect.getmembers(mod, inspect.isclass):
        fullname = '.'.join([mod.__name__,cls])
        if (typ.__module__.startswith(mod.__name__) and model.isRegistered(typ) 
            and txt in fullname ):
          it = QtGui.QTreeWidgetItem(root, [cls] )
          it.setFont(0,font)
      if it is not None:
        items.append(root)
    self.searchWidget_tree.clear()
    self.searchWidget_tree.insertTopLevelItems(0,items)
    self.selectFirstChild()
    return
  
  def updateTreeSelection(self):
    # update only
    items = self.searchWidget_tree.selectedItems()
    if len(items) > 1 :
      selected = items[-1]
      self.searchWidget_tree.setItemSelected()
  
  def selectFirstChild(self):
    if self.searchWidget_tree.topLevelItemCount() > 0:
      r = self.searchWidget_tree.topLevelItem(0)
      first = r.child(0)
      self.searchWidget_tree.setCurrentItem(first)
    return
  
  def selectedItem(self):
    item = self.searchWidget_tree.currentItem()
    if item is None:
      log.warning('No selected item')
      return None
    cls = str(item.text(0))
    mod = str(item.parent().text(0))
    targetClassName = '.'.join([mod,cls])
    return targetClassName
    
    
   
