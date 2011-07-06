#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('searchview')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt

from searchStruct import Ui_Search_Structure

class SearchStructDialog(QtGui.QDialog, Ui_Search_Structure):

  def __init__(self, parent=None):
    QtGui.QDialog.__init__(self, parent)
    # draw the window
    self.setupUi(self)
    self.setupSignals()
    self.setupData()
    return
  
  def setupSignals(self):
    self.dialog_search_structure_buttonbox.accepted.connect(self.search)
    #self.buttonBox.accepted.connect(parent.)
    #, SIGNAL(accepted()), this, SLOT(accept()));
    # connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    return
  
  def setupData(self):
    ''' put some items in the treeview '''
    #self.treeView
    print 'parent is ',type(self.parent()), self.parent()
    print 'current tab is', self.parent().currentTab()
    return
  
  def search(self):
    log.debug('searching....')
    tab = self.parent().currentTab()
    if tab is not None:
      structs, gitemgroup = tab.searchStructure()
      log.debug('The tab has found %d instances'%(len(structs)))
    return 
  
  
   
