#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

import logging

class StatusBarHandler(logging.Handler):
  def __init__(self, statusbar):
    self.statusbar = statusbar
    logging.Handler.__init__(self)
  def emit(self, record):
    self.statusbar.showMessage(record.getMessage(), 2000)
  

