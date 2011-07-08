#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

log = logging.getLogger('addmoduleview')

from PyQt4 import QtGui, QtCore, QtOpenGL
from PyQt4.Qt import Qt
import inspect

from addmodule import Ui_addModuleDialog

class AddModuleDialog(QtGui.QDialog, Ui_addModuleDialog):

  def __init__(self, parent=None):
    QtGui.QDialog.__init__(self, parent)
    # draw the window
    self.setupUi(self)
    self.setupSignals()
    self.setupData()
    return
      
  def setupSignals(self):
    self.buttonBox.accepted.connect(self.addModule)
    return
  
  def setupData(self):
    ''' init our state and fill our tree'''
    return
  
  def addModule(self):
    ''' get the current selection and launch the search on it'''
    # lock on target module
    targetModule = str(self.lineEdit.text())
    if targetModule is None:
      return
    log.debug('searching module %s....'%(targetModule))
    try:
      mod = __import__(targetModule, globals(), locals(), [], -1)
    except ImportError:
      log.warning('No such module in python path :%s'%(targetModule))
      self.reject()
    # done
    log.info('module %s has been imported'%(targetModule))
    return 
  

