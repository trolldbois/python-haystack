#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''
Total ripoff of 
http://www.codef00.com/projects#qhexview
'''

import sys
import logging
import argparse
import ctypes

log = logging.getLogger('qhexedit')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt

from PyQt4.QtGui import * #QFont, QFontMetrics, QMenu, QClipboard, QApplication, QFontDialog
from PyQt4.QtCore import * #SIGNAL, SLOT, QSignalMapper, QTextStream, QString

import string

#==================== tools

#we are not a DSP
CHAR_BIT = 8

#where is QtGlobal ?
def qBound(mini, value, maxi):
  return max(mini, min(value, maxi))


#def tr comme un string
tr=QString

class QHexeditWidget(QtGui.QAbstractScrollArea):
  highlightingNone=0
  highlightingData=1
  highlightingAscii=2
  
  def __init__(self, parent = None):
    QtGui.QAbstractScrollArea.__init__(self, parent)
    self.data = None
    self.row_width = 16    
    self.word_width = 1
    self.address_color = Qt.red
    self.show_hex = True
    self.show_ascii = True
    self.show_address = True
    #self.show_comments = True
    self.origin =0
    self.address_offset = 0
    self.selection_start = -1
    self.selection_end = -1
    self.highlighting = self.highlightingNone
    self.even_word = Qt.blue
    self.non_printable_text = Qt.red
    self.unprintable_char = '.'
    self.show_line1 = True
    self.show_line2 = True
    self.show_line3 = True
    self.show_address_separator = True
    # default to a simple monospace font
    self.setFont(QFont("Monospace", 8))
    self.setShowAddressSeparator(True)
    return 
  
  def setShowAddressSeparator(self, value):
    self.show_address_separator = value
    self.updateScrollbars()
    return
    
  def formatAddress(self, address):
    return self.format_address(address, self.show_address_separator)

  def format_address(self, address, showSep=False) :
    if showSep:
      sep = ':'
    s = ctypes.sizeof(ctypes.c_void_p)
    if s == 4:
      return QString("%04x%s%04x"% ((address >> 16) & 0xffff, sep, address & 0xffff)   )	
    elif s == 8:
      return QString("%08x%s%08x"% ((address >> 32) & 0xffffffff, sep, address & 0xffffffff)  )
    return

  def is_printable(self, ch):
    return ch in string.printable
    	
  '''
  // Name: add_toggle_action_to_menu(QMenu *menu, const QString &caption, bool checked, QObject *receiver, const char *slot)
  // Desc: convenience function used to add a checkable menu item to the context menu
  '''
  def add_toggle_action_to_menu(self, menu, caption, checked, call ):
    action = QAction(caption, menu)
    action.setCheckable(True)
    action.setChecked(checked)
    menu.addAction(action)
    self.connect(action, SIGNAL('toggled(bool)'), call)
    return action


  def repaint(self):
    self.viewport().repaint()
    return

  ''' 
  Name: dataSize() const
  Desc: returns how much data we are viewing
  '''
  def dataSize(self):
    if self.data is not None:
      return self.data.size()
    else:
      return 0

  '''
  Name: setFont(const QFont &f)
  Desc: overloaded version of setFont, calculates font metrics for later
  '''
  def setFont(self, f):
    # recalculate all of our metrics/offsets
    fm = QFontMetrics(f)
    self.font_width  = fm.width('X')
    self.font_height = fm.height()
    self.updateScrollbars()
    # TODO: assert that we are using a fixed font & find out if we care?
    QAbstractScrollArea.setFont(self,f)
    return

  ''' 
  Name: createStandardContextMenu()
  Desc: creates the 'standard' context menu for the widget
  '''
  def createStandardContextMenu(self):
    menu = QMenu(self)
    menu.addAction(tr("Set &Font"), self.mnuSetFont )
    menu.addSeparator()
    self.add_toggle_action_to_menu(menu, tr("Show A&ddress"), self.show_address, self.setShowAddress )
    self.add_toggle_action_to_menu(menu, tr("Show &Hex"), self.show_hex, self.setShowHexDump )
    self.add_toggle_action_to_menu(menu, tr("Show &Ascii"), self.show_ascii, self.setShowAsciiDump )
    #self.add_toggle_action_to_menu(menu, tr("Show &Comments"), self.show_comments, self.setShowComments )

    wordWidthMapper = QSignalMapper(menu)
    wordMenu = QMenu(tr("Set Word Width"), menu)
    a1 = self.add_toggle_action_to_menu(wordMenu, tr("1 Byte"), self.word_width == 1, wordWidthMapper.map  )
    a2 = self.add_toggle_action_to_menu(wordMenu, tr("2 Bytes"), self.word_width == 2, wordWidthMapper.map )
    a3 = self.add_toggle_action_to_menu(wordMenu, tr("4 Bytes"), self.word_width == 4, wordWidthMapper.map )
    a4 = self.add_toggle_action_to_menu(wordMenu, tr("8 Bytes"), self.word_width == 8, wordWidthMapper.map )
    wordWidthMapper.setMapping(a1, 1)
    wordWidthMapper.setMapping(a2, 2)
    wordWidthMapper.setMapping(a3, 4)
    wordWidthMapper.setMapping(a4, 8)
    self.connect(wordWidthMapper, SIGNAL('mapped(int)'), self.setWordWidth)

    rowWidthMapper = QSignalMapper(menu)
    rowMenu = QMenu(tr("Set Row Width"), menu)
    a5 = self.add_toggle_action_to_menu(rowMenu, tr("1 Word"), self.row_width == 1, rowWidthMapper.map)
    a6 = self.add_toggle_action_to_menu(rowMenu, tr("2 Words"), self.row_width == 2, rowWidthMapper.map)
    a7 = self.add_toggle_action_to_menu(rowMenu, tr("4 Words"), self.row_width == 4, rowWidthMapper.map)
    a8 = self.add_toggle_action_to_menu(rowMenu, tr("8 Words"), self.row_width == 8, rowWidthMapper.map)
    a9 = self.add_toggle_action_to_menu(rowMenu, tr("16 Words"), self.row_width == 16, rowWidthMapper.map)
    rowWidthMapper.setMapping(a5, 1)
    rowWidthMapper.setMapping(a6, 2)
    rowWidthMapper.setMapping(a7, 4)
    rowWidthMapper.setMapping(a8, 8)
    rowWidthMapper.setMapping(a9, 16)
    self.connect(rowWidthMapper, SIGNAL('mapped(int)'), self.setRowWidth)

    menu.addSeparator()
    menu.addMenu(wordMenu)
    menu.addMenu(rowMenu)

    menu.addSeparator()
    menu.addAction(tr("&Copy Selection To Clipboard"), self.mnuCopy)
    return menu

  '''
  Name: contextMenuEvent(QContextMenuEvent *event)
  Desc: default context menu event, simply shows standard menu
  '''
  def contextMenuEvent(self, event):
    menu = self.createStandardContextMenu()
    menu.exec_(event.globalPos())
    del menu
    return 
  

  '''
  Name: mnuCopy()
  Desc:
  '''
  def mnuCopy(self):
    if not (self.hasSelectedText()) :
      return
      
    s = QString
    ss = QTextStream(s)
    # current actual offset (in bytes)
    chars_per_row = self.bytesPerRow()
    offset = self.verticalScrollBar().value() * chars_per_row

    if (self.origin != 0) :
      if (offset > 0) :
        offset += self.origin
        offset -= self.chars_per_row

    end   = max(self.selection_start,self.selection_end)
    start = min(self.selection_start,self.selection_end)
    data_size      = self.dataSize()

    #offset now refers to the first visible byte
    while (offset < end) :
      if ((offset + chars_per_row) > start) :
        self.data.seek(offset)
        row_data = self.data.read(chars_per_row)

        if not (row_data is None) :
          if (self.show_address) :
            address_rva = self.address_offset + offset
            addressBuffer = self.formatAddress(address_rva)
            ss += addressBuffer
            ss += '|'
          if (show_hex_) :
            self.drawHexDumpToBuffer(ss, offset, data_size, row_data)
            ss += "|"
          if (show_ascii_) :
            self.drawAsciiDumpToBuffer(ss, offset, data_size, row_data)
            ss += "|"
          #if (self.show_comments and self.comment_server) :
          #  self.drawCommentsToBuffer(ss, offset, data_size)
        #
        ss+="\n"
      offset += chars_per_row
    QApplication.clipboard(self).setText(s)
    QApplication.clipboard(self).setText(s, QClipboard.Selection)
    return

  '''
  Name: mnuSetFont()
  Desc: slot used to set the font of the widget based on dialog selector
  '''
  def mnuSetFont(self) :
    font, boolean = QFontDialog.getFont(self.font(), self)
    self.setFont(font)
    return

  '''
  // Name: clear()
  // Desc: clears all data from the view
  '''
  def clear(self) :
    if (self.data != 0) :
      self.data.clear()
    self.repaint()
    return 
  
  '''
  // Name: hasSelectedText() const
  // Desc: returns true if any text is selected
  '''
  def hasSelectedText(self) :
    return not(self.selection_start == -1 or self.selection_end == -1)

  '''
  // Name: isInViewableArea(int index) const
  // Desc: returns true if the word at the given index is in the viewable area
  '''
  def isInViewableArea(self, index) : 
    firstViewableWord = self.verticalScrollBar().value() * self.row_width
    viewableLines     = self.viewport().height() / self.font_height
    viewableWords     = viewableLines * self.row_width
    lastViewableWord  = firstViewableWord + viewableWords
    return index >= firstViewableWord and index < lastViewableWord

  '''
  // Name: keyPressEvent(QKeyEvent *event)
  // Desc:
  '''
  def keyPressEvent(self, event) :
    if (event.modifiers() & Qt.ControlModifier) :
      key = event.key()
      if key == Qt.Key_A:
        self.selectAll()
        self.repaint()
      elif key == Qt.Key_Home:
        self.scrollTo(0)
      elif key == Qt.Key_End:
        self.scrollTo(dataSize() - self.bytesPerRow())
      elif key == Qt.Key_Down:
        while True:
          offset = self.verticalScrollBar().value() * self.bytesPerRow()
          if (self.origin != 0) :
            if (offset > 0) :
              offset += self.origin
              offset -= self.bytesPerRow()
          if(offset + 1 < self.dataSize()) :
            self.scrollTo(offset + 1)
          #return so we don't pass on the key event
          return
      elif key == Qt.Key_Up:
        while True:
          offset = self.verticalScrollBar().value() * self.bytesPerRow()
          if(self.origin != 0):
            if(offset > 0) :
              offset += self.origin
              offset -= self.bytesPerRow()
          if(offset > 0) :
            self.scrollTo(offset - 1)
          #return so we don't pass on the key event
          return
    QAbstractScrollArea.keyPressEvent(self,event)
    return

  '''
  // Name: line3() const
  // Desc: returns the x coordinate of the 3rd line
  '''
  def line3(self):
    if(self.show_ascii) :
      elements = self.bytesPerRow()
      return self.asciiDumpLeft() + (elements * self.font_width) + (self.font_width / 2)
    else :
      return self.line2()
    
  '''
  // Name: line2() const
  // Desc: returns the x coordinate of the 2nd line
  '''
  def line2(self):
    if(self.show_hex) :
      elements = self.row_width * (self.charsPerWord() + 1) - 1
      return self.hexDumpLeft() + (elements * self.font_width) + (self.font_width / 2)
    else :
      return self.line1()


  '''
  // Name: line1() const
  // Desc: returns the x coordinate of the 1st line
  '''
  def line1(self)  :
    if(self.show_address) :
      elements = self.addressLen()
      return (elements * self.font_width) + (self.font_width / 2)
    else :
      return 0

  
  '''
  // Name: hexDumpLeft() const
  // Desc: returns the x coordinate of the hex-dump field left edge
  '''
  def hexDumpLeft(self) :
    return self.line1() + (self.font_width / 2)
  
  '''
  // Name: asciiDumpLeft() const
  // Desc: returns the x coordinate of the ascii-dump field left edge
  '''
  def asciiDumpLeft(self) :
    return self.line2() + (self.font_width / 2)
  
  '''
  // Name: commentLeft() const
  // Desc: returns the x coordinate of the comment field left edge
  '''
  #def commentLeft(self) :
  #  return self.line3() + (self.font_width / 2)
  
  '''
  // Name: charsPerWord() const
  // Desc: returns how many characters each word takes up
  '''
  def charsPerWord(self ) :
    return self.word_width * 2
  
  '''
  // Name: addressLen() const
  // Desc: returns the lenth in characters the address will take up
  '''
  def addressLen(self) :
    addressLength = (ctypes.sizeof(ctypes.c_void_p) * CHAR_BIT) / 4
    if self.show_address_separator:
      return addressLength + 1
    return addressLength + 0



  '''
  // Name: updateScrollbars()
  // Desc: recalculates scrollbar maximum value base on lines total and lines viewable
  '''
  def updateScrollbars(self):
    sz = self.dataSize()
    bpr = self.bytesPerRow()
    if sz % bpr  :
      horn = 1
    else :
      horn = 0
    self.verticalScrollBar().setMaximum(max(0, sz / bpr + horn - self.viewport().height() / self.font_height))
    self.horizontalScrollBar().setMaximum(max(0, (self.line3() - self.viewport().width()) / self.font_width))
    return



  '''
  // Name: scrollTo( offset)
  // Desc: scrolls view to given byte offset
  '''
  def scrollTo( self, offset) :
  
    bpr = self.bytesPerRow()
    self.origin = offset % bpr
    address = offset / bpr
  
    self.updateScrollbars()
  
    if(self.origin != 0) :
      address+=1
    self.verticalScrollBar().setValue(address)
    self.repaint()
    return

  def setSelected(self, start, length):
    self.selection_start = start
    self.selection_end = self.selection_start + length
    self.repaint()


  '''
  // Name: setShowAddress(bool show)
  // Desc: sets if we are to display the address column
  '''
  def setShowAddress(self, show) :
    self.show_address = show
    self.updateScrollbars()
    self.repaint()
    return
  
  '''
  // Name: setShowHexDump(bool show)
  // Desc: sets if we are to display the hex-dump column
  '''
  def setShowHexDump(self, show) :
    self.show_hex = show
    self.updateScrollbars()
    self.repaint()
    return

  '''
  // Name: setShowComments(bool show)
  // Desc: sets if we are to display the comments column
  '''
  #def setShowComments(self, show) :
  #  self.show_comments = show
  #  self.updateScrollbars()
  #  self.repaint()
  #  return
  
  '''
  // Name: setShowAsciiDump(bool show)
  // Desc: sets if we are to display the ascii-dump column
  '''
  def setShowAsciiDump(self, show) :
    self.show_ascii = show
    self.updateScrollbars()
    self.repaint()
    return

  '''
  // Name: setRowWidth(int rowWidth)
  // Desc: sets the row width (units is words)
  '''
  def setRowWidth(self, rowWidth) :
    self.row_width = rowWidth
    self.updateScrollbars()
    self.repaint()
    return
  
  '''
  // Name: setWordWidth(int wordWidth)
  // Desc: sets how many bytes represent a word
  '''
  def setWordWidth(self, wordWidth) :
    self.word_width = wordWidth
    self.updateScrollbars()
    self.repaint()
    return

  '''
  // Name: bytesPerRow() const
  '''
  def bytesPerRow(self) :
    return self.row_width * self.word_width
  

  '''
  // Name: pixelToWord(int x, int y) const
  '''
  def pixelToWord(self, x, y) :
    word = -1
    if self.highlighting == self.highlightingData:
      #// the right edge of a box is kinda quirky, so we pretend there is one
      #// extra character there
      x = qBound(self.line1(), x, self.line2() + self.font_width)
  
      #// the selection is in the data view portion
      x -= self.line1()
  
      #// scale x/y down to character from pixels
      if (x % self.font_width >= self.font_width / 2 ):
        x = x / self.font_width + 1
      else:
        x = x / self.font_width
      y /= self.font_height
  
      #// make x relative to rendering mode of the bytes
      x /= (self.charsPerWord() + 1)
    elif self.highlighting == self.highlightingAscii:
      x = qBound(self.asciiDumpLeft(), x, self.line3())
  
      #// the selection is in the ascii view portion
      x -= self.asciiDumpLeft()
  
      #// scale x/y down to character from pixels
      x /= self.font_width
      y /= self.font_height
  
      #// make x relative to rendering mode of the bytes
      x /= self.word_width
    else:
      #Q_ASSERT(0)
      pass
  
    #// starting offset in bytes
    start_offset = self.verticalScrollBar().value() * self.bytesPerRow()
  
    #// take into account the origin
    if(self.origin != 0) :
      if(start_offset > 0) :
        start_offset += self.origin
        start_offset -= self.bytesPerRow()
      
    
  
    #// convert byte offset to word offset, rounding up
    start_offset /= self.word_width
  
    if((self.origin % self.word_width) != 0) :
      start_offset += 1
    
  
    word = ((y * self.row_width) + x) + start_offset
  
    return word


  '''
  // Name: mouseDoubleClickEvent(QMouseEvent *event)
  '''
  def mouseDoubleClickEvent(self, event) :
    if(event.button() == Qt.LeftButton) :
      x = event.x() + self.horizontalScrollBar().value() * self.font_width
      y = event.y()
      if(x >= self.line1() and x < self.line2()) :
        self.highlighting = self.highlightingData
        offset = self.pixelToWord(x, y)
        byte_offset = offset * self.word_width
        if(self.origin) :
          if(self.origin % self.word_width) :
            byte_offset -= self.word_width - (self.origin % self.word_width)
        self.selection_start = byte_offset
        self.selection_end = self.selection_start + self.word_width
        self.repaint()
    return


  '''
  // Name: mousePressEvent(QMouseEvent *event)
  '''
  def mousePressEvent(self, event) :
    if(event.button() == Qt.LeftButton) :
      x = event.x() + self.horizontalScrollBar().value() * self.font_width
      y = event.y()

      if(x < self.line2()) :
        self.highlighting = self.highlightingData
      elif(x >= self.line2()) :
        self.highlighting = self.highlightingAscii
      
      offset = self.pixelToWord(x, y)
      byte_offset = offset * self.word_width
      if(self.origin) :
        if(self.origin % self.word_width) :
          byte_offset -= self.word_width - (self.origin % self.word_width)
      if(offset < self.dataSize()):
        self.selection_start = self.selection_end = byte_offset
      else :
        self.selection_start = self.selection_end = -1
      self.repaint()
    return
    
  '''
  // Name: mouseMoveEvent(QMouseEvent *event)
  '''
  def mouseMoveEvent(self, event) :
    if(self.highlighting != self.highlightingNone) :
      x = event.x() + self.horizontalScrollBar().value() * self.font_width
      y = event.y()

      offset = self.pixelToWord(x, y)

      if(self.selection_start != -1) :
        if(offset == -1) :
          self.selection_end = (self.row_width - self.selection_start) + self.selection_start
        else :
          byte_offset = (offset * self.word_width)
          if(self.origin) :
            if(self.origin % self.word_width) :
              byte_offset -= self.word_width - (self.origin % self.word_width)
          self.selection_end = byte_offset
        if(self.selection_end < 0) :
          self.selection_end = 0
        if(not self.isInViewableArea(self.selection_end)) :
          #// TODO: scroll to an appropriate location
          pass
      self.repaint()
    return

  '''
  // Name: mouseReleaseEvent(QMouseEvent *event)
  '''
  def mouseReleaseEvent(self, event) :
    if(event.button() == Qt.LeftButton) :
      self.highlighting = self.highlightingNone
    return

  '''
  // Name: setData(const QSharedPointer<QIODevice>& d)
  '''
  def setData(self, data) :
    if not isinstance(data,QIODevice) and not isinstance(data,QByteArray):
      # transform it
      ba = QByteArray.fromRawData(data)
      buf = QBuffer(ba)
      buf.open(QIODevice.ReadOnly)
      # save the ref otherwise gc collects it
      self.myPointerToTheData = ba
      d = buf
    else:
      d = data
    if (d.isSequential()  or  not d.size()) :
      b = QBuffer()
      b.setData(d.readAll())
      b.open(QBuffer.ReadOnly)
      self.data = QSharedPointer(b)
    else :
      self.data = d
    self.deselect()
    self.updateScrollbars()
    self.repaint()
    return

  '''
  // Name: resizeEvent(QResizeEvent *)
  '''
  def resizeEvent(self, event) :
    self.updateScrollbars()
    return

  '''
  // Name: setAddressOffset(address_t offset)
  '''
  def setAddressOffset(self, offset) :
    self.address_offset = offset
    return

  '''
  // Name: isSelected(int index) const
  '''
  def isSelected(self, index) :
    ret = False
    if(index < self.dataSize() ) :
      if(self.selection_start != self.selection_end) :
        if(self.selection_start < self.selection_end) :
          ret = (index >= self.selection_start and index < self.selection_end)
        else :
          ret = (index >= self.selection_end and index < self.selection_start)
    return ret

  '''
  // Name: drawComments(QPainter &painter,  offset,  row, int size) const
  '''
  #def drawComments(self, painter,  offset,  row, size) :
  #  #Q_UNUSED(size)
  #  painter.setPen(QPen(self.palette().text().color()))
  #  address = self.address_offset + offset
  #  comment   = QString(self.comment_server.comment(address, self.word_width))
  #  painter.drawText(
  #    self.commentLeft(),
  #    row,
  #    comment.length() * self.font_width,
  #    self.font_height,
  #    Qt.AlignTop,
  #    comment
  #    )
  #  return

  '''
  // Name: drawAsciiDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const
  '''
  def drawAsciiDumpToBuffer(self, stream,  offset, size, row_data):
    #// i is the byte index
    chars_per_row = self.bytesPerRow()
    for i in range(0,chars_per_row) :
      index = offset + i
      if(index < size) :
        if(self.isSelected(index)) :
          ch = row_data[i]
          printable = ch in string.printable
          if printable:
            byteBuffer(ch)
          else:
            byteBuffer(self.unprintable_char)
          stream << byteBuffer
        else :
          stream << ' '
        
      else :
        break
    return

  '''
  // Name: drawCommentsToBuffer(QTextStream &stream,  offset, int size) const
  '''
  #def drawCommentsToBuffer(self, stream,  offset, size):
  #  #Q_UNUSED(size)
  #  address = self.address_offset + offset
  #  comment   = QString(self.comment_server.comment(address, self.word_width))
  #  stream << comment
  #  return

  '''
  // Name: format_bytes(const C &data_ref, int index) const
  // Desc: formats bytes in a way that's suitable for rendering in a hexdump
  //       having self as a separate function serves two purposes.
  //       #1 no code duplication between the buffer and QPainter versions
  //       #2 self encourages NRVO of the return value more than an integrated
  '''
  def format_bytes(self, row_data, index):
    #union :
    #  quint64 q
    #  quint32 d
    #  quint16 w
    #  quint8  b
    value = 0 
    byte_buffer = [0]*32
    if self.word_width == 1 :
      value |= (ord(row_data[index + 0]) & 0xff)
      byte_buffer = "%02x"% value
    elif self.word_width == 2 :
      value |= (ord(row_data[index + 0]) & 0xff)
      value |= (ord(row_data[index + 1]) & 0xff) << 8
      byte_buffer="%04x"%w
    elif self.word_width == 4 :
      value |= (ord(row_data[index + 0]) & 0xff)
      value |= (ord(row_data[index + 1]) & 0xff) << 8
      value |= (ord(row_data[index + 2]) & 0xff) << 16
      value |= (ord(row_data[index + 3]) & 0xff) << 24
      byte_buffer = "%08x"% value
    elif self.word_width == 8 :
      #// we need the cast to ensure that it won't assume 32-bit
      #// and drop bits shifted more that 31
      value |= (ord(row_data[index + 0]) & 0xff)
      value |= (ord(row_data[index + 1]) & 0xff) << 8
      value |= (ord(row_data[index + 2]) & 0xff) << 16
      value |= (ord(row_data[index + 3]) & 0xff) << 24
      value |= (ord(row_data[index + 4]) & 0xff) << 32
      value |= (ord(row_data[index + 5]) & 0xff) << 40
      value |= (ord(row_data[index + 6]) & 0xff) << 48
      value |= (ord(row_data[index + 7]) & 0xff) << 56
      byte_buffer = "%016llx"% value
    return byte_buffer

  '''
  // Name: drawHexDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const
  '''
  def drawHexDumpToBuffer(self, stream,  offset, size, row_data) :
    #Q_UNUSED(size)
    #// i is the word we are currently rendering
    for i in range(0, self.row_width) :
      #// index of first byte of current 'word'
      index = offset + (i * self.word_width)
      #// equal <=, not < because we want to test the END of the word we
      #// about to render, not the start, it's allowed to end at the very last
      #// byte
      if(index + self.word_width <= size) :
        byteBuffer = QString(self.format_bytes(row_data, i * self.word_width))
        if(self.isSelected(index)) :
          stream << byteBuffer
        else :
          stream << QString(byteBuffer.length(), ' ')
        if(i != (self.row_width - 1)) :
          stream << ' '
      else :
        break
    return
    
  '''
  // Name: drawHexDump(QPainter &painter,  offset,  row, int size, int &word_count, const QByteArray &row_data) const
  '''
  def drawHexDump(self, painter,  offset,  row, size, word_count, row_data):
    hex_dump_left = self.hexDumpLeft()
    #// i is the word we are currently rendering
    for i in range(0,self.row_width) :
      #// index of first byte of current 'word'
      index = offset + (i * self.word_width)
      #// equal <=, not < because we want to test the END of the word we
      #// about to render, not the start, it's allowed to end at the very last
      #// byte
      if(index + self.word_width <= size) :
        byteBuffer = QString(self.format_bytes(row_data, i * self.word_width))
        drawLeft = hex_dump_left + (i * (self.charsPerWord() + 1) * self.font_width)
        if(self.isSelected(index)) :
          painter.fillRect(
            drawLeft,
            row,
            self.charsPerWord() * self.font_width,
            self.font_height,
            self.palette().highlight()
          )

          #// should be highlight the space between us and the next word?
          if(i != (self.row_width - 1)) :
            if(self.isSelected(index + 1)) :
              painter.fillRect(
                drawLeft + self.font_width,
                row,
                self.charsPerWord() * self.font_width,
                self.font_height,
                self.palette().highlight()
                )
          painter.setPen(QPen(self.palette().highlightedText().color()))
        else :
          if (word_count & 1):
            painter.setPen(QPen(self.even_word ))
            painter.setPen(QPen(self.palette().text().color()))
        
        painter.drawText(
          drawLeft,
          row,
          byteBuffer.length() * self.font_width,
          self.font_height,
          Qt.AlignTop,
          byteBuffer
          )

        word_count+=1
      else :
        break
    return

  '''
  // Name: drawAsciiDump(QPainter &painter,  offset,  row, int size, const QByteArray &row_data) const
  '''
  def drawAsciiDump(self, painter,  offset,  row, size, row_data) :
    ascii_dump_left = self.asciiDumpLeft()

    #// i is the byte index
    chars_per_row = self.bytesPerRow()
    for i in range(0,chars_per_row) :
      index = offset + i
      if(index < size) :
        ch        = row_data[i]
        drawLeft   = ascii_dump_left + i * self.font_width
        printable = self.is_printable(ch)
        #// drawing a selected character
        if(self.isSelected(index)) :
          painter.fillRect(
            drawLeft,
            row,
            self.font_width,
            self.font_height,
            self.palette().highlight()
            )
          painter.setPen(QPen(self.palette().highlightedText().color()))
        else :
          if printable:
            painter.setPen(QPen(self.palette().text().color()))
          else:
            painter.setPen(QPen(self.non_printable_text))
        if printable:
          byteBuffer = QString(ch)
        else:
          byteBuffer = QString(self.unprintable_char)
        painter.drawText(
          drawLeft,
          row,
          self.font_width,
          self.font_height,
          Qt.AlignTop,
          byteBuffer
          )
      else :
        break
    return

  '''
  // Name: paintEvent(QPaintEvent *)
  '''
  def paintEvent(self, event) :

    painter = QPainter(self.viewport())
    painter.translate(-self.horizontalScrollBar().value() * self.font_width, 0)
    word_count = 0

    #// pixel offset of self row
    row = 0
    chars_per_row = self.bytesPerRow()
    #// current actual offset (in bytes)
    offset = self.verticalScrollBar().value() * chars_per_row

    if(self.origin != 0) :
      if(offset > 0) :
        offset += self.origin
        offset -= chars_per_row
      else :
        self.origin = 0
        self.updateScrollbars()

    data_size     = self.dataSize()
    widget_height = self.height()

    while(row + self.font_height < widget_height ) and (offset < data_size) :
      self.data.seek(offset)
      row_data = self.data.read(chars_per_row)
      if( row_data is not None ) : # != '' ?
        if(self.show_address) :
          address_rva = self.address_offset + offset
          addressBuffer = self.formatAddress(address_rva)
          painter.setPen(QPen(self.address_color))
          painter.drawText(0, row, addressBuffer.length() * self.font_width, self.font_height, Qt.AlignTop, addressBuffer)

        if(self.show_hex) :
          self.drawHexDump(painter, offset, row, data_size, word_count, row_data)
        if(self.show_ascii) :
          self.drawAsciiDump(painter, offset, row, data_size, row_data)
        #if(self.show_comments and self.comment_server) :
        #  self.drawComments(painter, offset, row, data_size)
      offset += chars_per_row
      row += self.font_height

    painter.setPen(QPen(self.palette().shadow().color()))

    if(self.show_address and self.show_line1) :
      line1_x = self.line1()
      painter.drawLine(line1_x, 0, line1_x, widget_height)

    if(self.show_hex  and  self.show_line2) :
      line2_x = self.line2()
      painter.drawLine(line2_x, 0, line2_x, widget_height)

    if(self.show_ascii  and  self.show_line3) :
      line3_x = self.line3()
      painter.drawLine(line3_x, 0, line3_x, widget_height)

    return

  '''
  // Name: selectAll()
  '''
  def selectAll(self) :
    self.selection_start = 0
    self.selection_end   = self.dataSize()
    return

  '''
  // Name: deselect()
  '''
  def deselect(self) :
    self.selection_start = -1
    self.selection_end   = -1
    return

  '''
  // Name: allBytes() const
  '''
  def allBytes(self) :
    self.data.seek(0)
    return self.data.readAll()

  '''
  // Name: selectedBytes() const
  '''
  def selectedBytes(self ):
    if(self.hasSelectedText()) :
      s = min(self.selection_start, self.selection_end)
      e = max(self.selection_start, self.selection_end)
      self.data.seek(s)
      return self.data.read(e - s)
    return QByteArray()

  '''
  // Name: selectedBytesAddress() const
  '''
  def selectedBytesAddress(self) :
    select_base = min(self.selection_start, self.selection_end)
    return select_base + self.address_offset

  '''
  // Name: selectedBytesSize() const
  '''
  def selectedBytesSize(self):
    if(self.selection_end > self.selection_start) :
      ret = self.selection_end - self.selection_start
    else :
      ret = self.selection_start - self.selection_end
    return ret

  '''
  // Name: addressOffset() const
  '''
  def addressOffset(self):
    return self.address_offset

  '''
  // Name: setCommentServer(const QSharedPointer<CommentServerInterface> &p)
  '''
  #def setCommentServer(self, p) :
  #  self.comment_server = p
  #  return

  '''
  // Name: commentServer() const
  '''
  #def commentServer(self):
  #  return self.comment_server

  '''
  // Name: showHexDump() const
  '''
  def showHexDump(self) :
    return self.show_hex

  '''
  // Name: showAddress() const
  '''
  def showAddress(self):
    return self.show_address

  '''
  // Name: showAsciiDump() const
  '''
  def showAsciiDump(self):
    return self.show_ascii

  '''
  // Name: showComments() const
  '''
  def mshowComments(self):
    return self.show_comments

  '''
  // Name: wordWidth() const
  '''
  def wordWidth(self) :
    return self.word_width

  '''
  // Name: rowWidth() const
  '''
  def rowWidth(self) :
    return self.row_width

  '''
  // Name: firstVisibleAddress() const
  '''
  def firstVisibleAddress(self):
    #// current actual offset (in bytes)
    chars_per_row = self.bytesPerRow()
    offset = self.verticalScrollBar().value() * chars_per_row
    if(self.origin != 0) :
      if(offset > 0) :
        offset += self.origin
        offset -= chars_per_row
    return offset + self.addressOffset()

  @classmethod
  def fromBuffer(cls, data):
    #ba = QByteArray.fromRawData(data)
    #buf = QBuffer(ba)
    #buf.open(QIODevice.ReadOnly)
    me = cls()
    me.setData(data)
    # save the ref otherwise gc collects it
    #me.myPointerToTheData = ba\
    #me.fromBuffer(data)
    return me

  @classmethod
  def fromFile(cls, filename):
    qf = QFile(filename)
    qf.open(QIODevice.ReadOnly)
    me = cls()
    me.setData(qf)
    return me

####--------------

def gui(opts):
  app = QtGui.QApplication(sys.argv)
  data = opts.file.read()
  hexedit = QHexeditWidget.fromBuffer(data)
  #hexedit = QHexeditWidget.fromFile(opts.file.name)
  hexedit.show()
  sys.exit(app.exec_())

def argparser():
  rootparser = argparse.ArgumentParser(prog='haystack-gui', description='Hexedit widget demo.')
  rootparser.add_argument('file', type=argparse.FileType('rb'), action='store', help='file to read')
  rootparser.set_defaults(func=gui)  
  return rootparser

def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  #logging.getLogger('haystack').setLevel(logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  

if __name__ == '__main__':
  main(sys.argv[1:])
