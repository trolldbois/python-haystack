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

# IMPORTANT: we need to keep the module hierarchy, otherwise the book register/singleton is dead
from haystack import model 

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
    ''' get the current selection and launch the search on it'''
    # lock on target classe name
    targetClassName = self.selectedItem()
    if targetClassName is None:
      return
    log.debug('searching....')
    tab = self.parent().currentTab()
    if tab is not None:
      structs, gitemgroup = tab.searchStructure(targetClassName)
      log.debug('The tab has found %d instances'%(len(structs)))
    return 
  
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
        if typ.__module__.startswith(mod.__name__) and model.isStructType(typ()):
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
    
    
   
