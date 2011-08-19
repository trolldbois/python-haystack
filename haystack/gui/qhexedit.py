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
log = logging.getLogger('qhexedit')

from PyQt4 import QtGui, QtCore
from PyQt4.Qt import Qt

from PyQt4.QtGui import * #QFont, QFontMetrics, QMenu, QClipboard, QApplication, QFontDialog
from PyQt4.QtCore import * #SIGNAL, SLOT, QSignalMapper, QTextStream, QString

import string

#==================== tools
def isPrintable(ch):
  return chr(ch) in string.printable

#def tr comme un string
tr=str

class QHexeditWidget(QtGui.QAbstractScrollArea):
  def __init__(self, file, parent = None):
    QtGui.QAbstractScrollArea.__init__(self, parent)
    self.row_width = 16    
    self.word_width = 1
    self.address_color = Qt.red
    self.show_hex = True
    self.show_ascii = True
    self.show_address = True
    self.show_comments = True
    self.origin =0
    self.address_offset = 0
    self.selection_start = -1
    self.selection_end = -1
    self.highlighting = 0 #Qt.Highlighting_None
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
    # me
    self.file = file
    return 
  
  def setShowAddressSeparator(self, value):
    self.show_address_separator = value
    self.updateScrollbars()
    return
    
  def formatAddress(self, address):
    return format_address(address, self.show_address_separator)

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
    menu.addAction(tr("Set &Font"), self, SLOT(mnuSetFont()))
    menu.addSeparator()
    self.add_toggle_action_to_menu(menu, tr("Show A&ddress"), self.show_address, self, SLOT('setShowAddress(bool)'))
    self.add_toggle_action_to_menu(menu, tr("Show &Hex"), self.show_hex, self, SLOT('setShowHexDump(bool)'))
    self.add_toggle_action_to_menu(menu, tr("Show &Ascii"), self.show_ascii, self, SLOT('setShowAsciiDump(bool)'))
    self.add_toggle_action_to_menu(menu, tr("Show &Comments"), self.show_comments, self, SLOT('setShowComments(bool)'))

    wordWidthMapper = QSignalMapper(menu)
    wordMenu = QMenu(tr("Set Word Width"), menu)
    a1 = self.add_toggle_action_to_menu(wordMenu, tr("1 Byte"), word_width_ == 1, wordWidthMapper, SLOT('map()'))
    a2 = self.add_toggle_action_to_menu(wordMenu, tr("2 Bytes"), word_width_ == 2, wordWidthMapper, SLOT('map()'))
    a3 = self.add_toggle_action_to_menu(wordMenu, tr("4 Bytes"), word_width_ == 4, wordWidthMapper, SLOT('map()'))
    a4 = self.add_toggle_action_to_menu(wordMenu, tr("8 Bytes"), word_width_ == 8, wordWidthMapper, SLOT('map()'))
    wordWidthMapper.setMapping(a1, 1)
    wordWidthMapper.setMapping(a2, 2)
    wordWidthMapper.setMapping(a3, 4)
    wordWidthMapper.setMapping(a4, 8)
    self.connect(wordWidthMapper, SIGNAL('mapped(int)'), SLOT('setWordWidth(int)'))

    rowWidthMapper = QSignalMapper(menu)
    rowMenu = QMenu(tr("Set Row Width"), menu)
    a5 = self.add_toggle_action_to_menu(rowMenu, tr("1 Word"), row_width_ == 1, rowWidthMapper, SLOT('map()'))
    a6 = self.add_toggle_action_to_menu(rowMenu, tr("2 Words"), row_width_ == 2, rowWidthMapper, SLOT('map()'))
    a7 = self.add_toggle_action_to_menu(rowMenu, tr("4 Words"), row_width_ == 4, rowWidthMapper, SLOT('map()'))
    a8 = self.add_toggle_action_to_menu(rowMenu, tr("8 Words"), row_width_ == 8, rowWidthMapper, SLOT('map()'))
    a9 = self.add_toggle_action_to_menu(rowMenu, tr("16 Words"), row_width_ == 16, rowWidthMapper, SLOT('map()'))
    rowWidthMapper.setMapping(a5, 1)
    rowWidthMapper.setMapping(a6, 2)
    rowWidthMapper.setMapping(a7, 4)
    rowWidthMapper.setMapping(a8, 8)
    rowWidthMapper.setMapping(a9, 16)
    self.connect(rowWidthMapper, SIGNAL('mapped(int)'), SLOT('setRowWidth(int)'))

    menu.addSeparator()
    menu.addMenu(wordMenu)
    menu.addMenu(rowMenu)

    menu.addSeparator()
    menu.addAction(tr("&Copy Selection To Clipboard"), self, SLOT(mnuCopy()))
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

        if not (row_data.isEmpty()) :
          if (self.show_address) :
            address_rva = self.address_offset + offset
            addressBuffer = formatAddress(address_rva)
            ss += addressBuffer
            ss += '|'
          if (show_hex_) :
            self.drawHexDumpToBuffer(ss, offset, data_size, row_data)
            ss += "|"
          if (show_ascii_) :
            self.drawAsciiDumpToBuffer(ss, offset, data_size, row_data)
            ss += "|"
          if (self.show_comments and self.comment_server) :
            self.drawCommentsToBuffer(ss, offset, data_size)
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
    self.setFont(QFontDialog.getFont(0, self.font(), self))
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
    viewableWords     = self.viewableLines * self.row_width
    lastViewableWord  = self.firstViewableWord + self.viewableWords
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
            self.scrollTo(offset + 1);

        #return so we don't pass on the key event
        return;
      elif key == Qt.Key_Up:
        while True:
          offset = self.verticalScrollBar().value() * self.bytesPerRow();
          if(origin_ != 0):
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
      elements = self.bytesPerRow();
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

  """
'''
// Name: hexDumpLeft() const
// Desc: returns the x coordinate of the hex-dump field left edge
'''
int QHexView.hexDumpLeft() const :
  return line1() + (font_width_ / 2);
}

'''
// Name: asciiDumpLeft() const
// Desc: returns the x coordinate of the ascii-dump field left edge
'''
int QHexView.asciiDumpLeft() const :
  return line2() + (font_width_ / 2);
}

'''
// Name: commentLeft() const
// Desc: returns the x coordinate of the comment field left edge
'''
int QHexView.commentLeft() const :
  return line3() + (font_width_ / 2);
}

'''
// Name: charsPerWord() const
// Desc: returns how many characters each word takes up
'''
 QHexView.charsPerWord() const :
  return word_width_ * 2;
}

'''
// Name: addressLen() const
// Desc: returns the lenth in characters the address will take up
'''
 QHexView.addressLen() const :
  static  addressLength = (sizeof(address_t) * CHAR_BIT) / 4;
  return addressLength + (show_address_separator_ ? 1 : 0);
}

  """

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
  def setShowComments(self, show) :
    self.show_comments = show
    self.updateScrollbars()
    self.repaint()
    return
  
  '''
  // Name: setShowAsciiDump(bool show)
  // Desc: sets if we are to display the ascii-dump column
  '''
  def setShowAsciiDump(self, show) :
    self.show_ascii = show
    self.updateScrollbars()
    self.repaint()
  }

  '''
  // Name: setRowWidth(int rowWidth)
  // Desc: sets the row width (units is words)
  '''
  de setRowWidth(self, rowWidth) :
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
  
"""
'''
// Name: pixelToWord(int x, int y) const
'''
int QHexView.pixelToWord(int x, int y) const :
  int word = -1;

  switch(highlighting_) :
  case Highlighting_Data:
    // the right edge of a box is kinda quirky, so we pretend there is one
    // extra character there
    x = qBound(line1(), x, line2() + font_width_);

    // the selection is in the data view portion
    x -= line1();

    // scale x/y down to character from pixels
    x = x / font_width_ + (x % font_width_ >= font_width_ / 2 ? 1 : 0);
    y /= font_height_;

    // make x relative to rendering mode of the bytes
    x /= (charsPerWord() + 1);
    break;
  case Highlighting_Ascii:
    x = qBound(asciiDumpLeft(), x, line3());

    // the selection is in the ascii view portion
    x -= asciiDumpLeft();

    // scale x/y down to character from pixels
    x /= font_width_;
    y /= font_height_;

    // make x relative to rendering mode of the bytes
    x /= word_width_;
    break;
  default:
    Q_ASSERT(0);
    break;
  }

  // starting offset in bytes
   start_offset = verticalScrollBar().value() * bytesPerRow();

  // take into account the origin
  if(origin_ != 0) :
    if(start_offset > 0) :
      start_offset += origin_;
      start_offset -= bytesPerRow();
    }
  }

  // convert byte offset to word offset, rounding up
  start_offset /= word_width_;

  if((origin_ % word_width_) != 0) :
    start_offset += 1;
  }

  word = ((y * row_width_) + x) + start_offset;

  return word;
}

'''
// Name: mouseDoubleClickEvent(QMouseEvent *event)
'''
void QHexView.mouseDoubleClickEvent(QMouseEvent *event) :
  if(event.button() == Qt.LeftButton) :
    x = event.x() + horizontalScrollBar().value() * font_width_;
    y = event.y();
    if(x >= line1() && x < line2()) :

      highlighting_ = Highlighting_Data;

      offset = pixelToWord(x, y);
      int byte_offset = offset * word_width_;
      if(origin_) :
        if(origin_ % word_width_) :
          byte_offset -= word_width_ - (origin_ % word_width_);
        }
      }

      selection_start_ = byte_offset;
      selection_end_ = selection_start_ + word_width_;
      repaint();
    }
  }
}

'''
// Name: mousePressEvent(QMouseEvent *event)
'''
void QHexView.mousePressEvent(QMouseEvent *event) :
  if(event.button() == Qt.LeftButton) :
    x = event.x() + horizontalScrollBar().value() * font_width_;
    y = event.y();

    if(x < line2()) :
      highlighting_ = Highlighting_Data;
    } else if(x >= line2()) :
      highlighting_ = Highlighting_Ascii;
    }

    offset = pixelToWord(x, y);
    int byte_offset = offset * word_width_;
    if(origin_) :
      if(origin_ % word_width_) :
        byte_offset -= word_width_ - (origin_ % word_width_);
      }
    }

    if(offset < dataSize()) :
      selection_start_ = selection_end_ = byte_offset;
    } else :
      selection_start_ = selection_end_ = -1;
    }
    repaint();
  }
}

'''
// Name: mouseMoveEvent(QMouseEvent *event)
'''
void QHexView.mouseMoveEvent(QMouseEvent *event) :
  if(highlighting_ != Highlighting_None) :
    x = event.x() + horizontalScrollBar().value() * font_width_;
    y = event.y();

    offset = pixelToWord(x, y);

    if(selection_start_ != -1) :
      if(offset == -1) :
        selection_end_ = (row_width_ - selection_start_) + selection_start_;
      } else :

        int byte_offset = (offset * word_width_);

        if(origin_) :
          if(origin_ % word_width_) :
            byte_offset -= word_width_ - (origin_ % word_width_);
          }

        }
        selection_end_ = byte_offset;
      }

      if(selection_end_ < 0) :
        selection_end_ = 0;
      }

      if(!isInViewableArea(selection_end_)) :
        // TODO: scroll to an appropriate location
      }

    }
    repaint();
  }
}

'''
// Name: mouseReleaseEvent(QMouseEvent *event)
'''
void QHexView.mouseReleaseEvent(QMouseEvent *event) :
  if(event.button() == Qt.LeftButton) :
    highlighting_ = Highlighting_None;
  }
}

'''
// Name: setData(const QSharedPointer<QIODevice>& d)
'''
void QHexView.setData(const QSharedPointer<QIODevice>& d) :
  if (d.isSequential() || !d.size()) :
    QBuffer *b = new QBuffer;
    b.setData(d.readAll());
    b.open(QBuffer.ReadOnly);
    data_ = QSharedPointer<QIODevice>(b);
  } else :
    data_ = d;
  }

  deselect();
  updateScrollbars();
  repaint();
}

'''
// Name: resizeEvent(QResizeEvent *)
'''
void QHexView.resizeEvent(QResizeEvent *) :
  updateScrollbars();
}

'''
// Name: setAddressOffset(address_t offset)
'''
void QHexView.setAddressOffset(address_t offset) :
  address_offset_ = offset;
}

'''
// Name: isSelected(int index) const
'''
bool QHexView.isSelected(int index) const :

  bool ret = false;
  if(index < static_cast<int>(dataSize())) :
    if(selection_start_ != selection_end_) :
      if(selection_start_ < selection_end_) :
        ret = (index >= selection_start_ && index < selection_end_);
      } else :
        ret = (index >= selection_end_ && index < selection_start_);
      }
    }
  }
  return ret;
}

'''
// Name: drawComments(QPainter &painter,  offset,  row, int size) const
'''
void QHexView.drawComments(QPainter &painter,  offset,  row, int size) const :

  Q_UNUSED(size);

  painter.setPen(QPen(palette().text().color()));

  const address_t address = address_offset_ + offset;
  const QString comment   = comment_server_.comment(address, word_width_);

  painter.drawText(
    commentLeft(),
    row,
    comment.length() * font_width_,
    font_height_,
    Qt.AlignTop,
    comment
    );
}

'''
// Name: drawAsciiDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const
'''
void QHexView.drawAsciiDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const :
  // i is the byte index
  chars_per_row = bytesPerRow();
  for(int i = 0; i < chars_per_row; ++i) :

    index = offset + i;

    if(index < size) :

      if(isSelected(index)) :
        const unsigned char ch = row_data[i];
        const bool printable = is_printable(ch) && ch != '\f' && ch != '\t' && ch != '\r' && ch != '\n' && ch < 0x80;
        const char byteBuffer(printable ? ch : unprintable_char_);
        stream << byteBuffer;
      } else :
        stream << ' ';
      }
    } else :
      break;
    }
  }
}

'''
// Name: drawCommentsToBuffer(QTextStream &stream,  offset, int size) const
'''
void QHexView.drawCommentsToBuffer(QTextStream &stream,  offset, int size) const :
  Q_UNUSED(size);
  const address_t address = address_offset_ + offset;
  const QString comment   = comment_server_.comment(address, word_width_);
  stream << comment;
}

'''
// Name: format_bytes(const C &data_ref, int index) const
// Desc: formats bytes in a way that's suitable for rendering in a hexdump
//       having self as a separate function serves two purposes.
//       #1 no code duplication between the buffer and QPainter versions
//       #2 self encourages NRVO of the return value more than an integrated
'''
QString QHexView.format_bytes(const QByteArray &row_data, int index) const :
  union :
    quint64 q;
    quint32 d;
    quint16 w;
    quint8  b;
  } value = : 0 };

  char byte_buffer[32];

  switch(word_width_) :
  case 1:
    value.b |= (row_data[index + 0] & 0xff);
    qsnprintf(byte_buffer, sizeof(byte_buffer), "%02x", value.b);
    break;
  case 2:
    value.w |= (row_data[index + 0] & 0xff);
    value.w |= (row_data[index + 1] & 0xff) << 8;
    qsnprintf(byte_buffer, sizeof(byte_buffer), "%04x", value.w);
    break;
  case 4:
    value.d |= (row_data[index + 0] & 0xff);
    value.d |= (row_data[index + 1] & 0xff) << 8;
    value.d |= (row_data[index + 2] & 0xff) << 16;
    value.d |= (row_data[index + 3] & 0xff) << 24;
    qsnprintf(byte_buffer, sizeof(byte_buffer), "%08x", value.d);
    break;
  case 8:
    // we need the cast to ensure that it won't assume 32-bit
    // and drop bits shifted more that 31
    value.q |= static_cast<quint64>(row_data[index + 0] & 0xff);
    value.q |= static_cast<quint64>(row_data[index + 1] & 0xff) << 8;
    value.q |= static_cast<quint64>(row_data[index + 2] & 0xff) << 16;
    value.q |= static_cast<quint64>(row_data[index + 3] & 0xff) << 24;
    value.q |= static_cast<quint64>(row_data[index + 4] & 0xff) << 32;
    value.q |= static_cast<quint64>(row_data[index + 5] & 0xff) << 40;
    value.q |= static_cast<quint64>(row_data[index + 6] & 0xff) << 48;
    value.q |= static_cast<quint64>(row_data[index + 7] & 0xff) << 56;
    qsnprintf(byte_buffer, sizeof(byte_buffer), "%016llx", value.q);
    break;
  }

  return byte_buffer;
}

'''
// Name: drawHexDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const
'''
void QHexView.drawHexDumpToBuffer(QTextStream &stream,  offset, int size, const QByteArray &row_data) const :

  Q_UNUSED(size);

  // i is the word we are currently rendering
  for(int i = 0; i < row_width_; ++i) :

    // index of first byte of current 'word'
    index = offset + (i * word_width_);

    // equal <=, not < because we want to test the END of the word we
    // about to render, not the start, it's allowed to end at the very last
    // byte
    if(index + word_width_ <= size) :
      const QString byteBuffer = format_bytes(row_data, i * word_width_);

      if(isSelected(index)) :
        stream << byteBuffer;
      } else :
        stream << QString(byteBuffer.length(), ' ');
      }

      if(i != (row_width_ - 1)) :
        stream << ' ';
      }
    } else :
      break;
    }
  }
}

'''
// Name: drawHexDump(QPainter &painter,  offset,  row, int size, int &word_count, const QByteArray &row_data) const
'''
void QHexView.drawHexDump(QPainter &painter,  offset,  row, int size, int &word_count, const QByteArray &row_data) const :
  hex_dump_left = hexDumpLeft();

  // i is the word we are currently rendering
  for(int i = 0; i < row_width_; ++i) :

    // index of first byte of current 'word'
    index = offset + (i * word_width_);

    // equal <=, not < because we want to test the END of the word we
    // about to render, not the start, it's allowed to end at the very last
    // byte
    if(index + word_width_ <= size) :

      const QString byteBuffer = format_bytes(row_data, i * word_width_);

      drawLeft = hex_dump_left + (i * (charsPerWord() + 1) * font_width_);

      if(isSelected(index)) :
        painter.fillRect(
          drawLeft,
          row,
          charsPerWord() * font_width_,
          font_height_,
          palette().highlight()
        );

        // should be highlight the space between us and the next word?
        if(i != (row_width_ - 1)) :
          if(isSelected(index + 1)) :
            painter.fillRect(
              drawLeft + font_width_,
              row,
              charsPerWord() * font_width_,
              font_height_,
              palette().highlight()
              );
          }
        }

        painter.setPen(QPen(palette().highlightedText().color()));
      } else :
        painter.setPen(QPen((word_count & 1) ? even_word_ : palette().text().color()));
      }

      painter.drawText(
        drawLeft,
        row,
        byteBuffer.length() * font_width_,
        font_height_,
        Qt.AlignTop,
        byteBuffer
        );

      ++word_count;
    } else :
      break;
    }
  }
}

'''
// Name: drawAsciiDump(QPainter &painter,  offset,  row, int size, const QByteArray &row_data) const
'''
void QHexView.drawAsciiDump(QPainter &painter,  offset,  row, int size, const QByteArray &row_data) const :
  ascii_dump_left = asciiDumpLeft();

  // i is the byte index
  chars_per_row = bytesPerRow();
  for(int i = 0; i < chars_per_row; ++i) :

    index = offset + i;

    if(index < size) :
      const char ch        = row_data[i];
      drawLeft   = ascii_dump_left + i * font_width_;
      const bool printable = is_printable(ch);

      // drawing a selected character
      if(isSelected(index)) :

        painter.fillRect(
          drawLeft,
          row,
          font_width_,
          font_height_,
          palette().highlight()
          );

        painter.setPen(QPen(palette().highlightedText().color()));

      } else :
        painter.setPen(QPen(printable ? palette().text().color() : non_printable_text_));
      }

      const QString byteBuffer(printable ? ch : unprintable_char_);

      painter.drawText(
        drawLeft,
        row,
        font_width_,
        font_height_,
        Qt.AlignTop,
        byteBuffer
        );
    } else :
      break;
    }
  }
}

'''
// Name: paintEvent(QPaintEvent *)
'''
void QHexView.paintEvent(QPaintEvent *) :

  QPainter painter(viewport());
  painter.translate(-horizontalScrollBar().value() * font_width_, 0);

  int word_count = 0;

  // pixel offset of self row
   row = 0;

  chars_per_row = bytesPerRow();

  // current actual offset (in bytes)
   offset = verticalScrollBar().value() * chars_per_row;

  if(origin_ != 0) :
    if(offset > 0) :
      offset += origin_;
      offset -= chars_per_row;
    } else :
      origin_ = 0;
      updateScrollbars();
    }
  }

   data_size     = static_cast<>(dataSize());
   widget_height = static_cast<>(height());

  while(row + font_height_ < widget_height && offset < data_size) :

    data_.seek(offset);
    const QByteArray row_data = data_.read(chars_per_row);

    if(!row_data.isEmpty()) :
      if(show_address_) :
        const address_t address_rva = address_offset_ + offset;
        const QString addressBuffer = formatAddress(address_rva);
        painter.setPen(QPen(address_color_));
        painter.drawText(0, row, addressBuffer.length() * font_width_, font_height_, Qt.AlignTop, addressBuffer);
      }

      if(show_hex_) :
        drawHexDump(painter, offset, row, data_size, word_count, row_data);
      }

      if(show_ascii_) :
        drawAsciiDump(painter, offset, row, data_size, row_data);
      }

      if(show_comments_ && comment_server_) :
        drawComments(painter, offset, row, data_size);
      }
    }

    offset += chars_per_row;
    row += font_height_;
  }

  painter.setPen(QPen(palette().shadow().color()));

  if(show_address_ && show_line1_) :
    line1_x = line1();
    painter.drawLine(line1_x, 0, line1_x, widget_height);
  }

  if(show_hex_ && show_line2_) :
    line2_x = line2();
    painter.drawLine(line2_x, 0, line2_x, widget_height);
  }

  if(show_ascii_ && show_line3_) :
    line3_x = line3();
    painter.drawLine(line3_x, 0, line3_x, widget_height);
  }
}

'''
// Name: selectAll()
'''
void QHexView.selectAll() :
  selection_start_ = 0;
  selection_end_   = dataSize();
}

'''
// Name: deselect()
'''
void QHexView.deselect() :
  selection_start_ = -1;
  selection_end_   = -1;
}

'''
// Name: allBytes() const
'''
QByteArray QHexView.allBytes() const :
  data_.seek(0);
  return data_.readAll();
}

'''
// Name: selectedBytes() const
'''
QByteArray QHexView.selectedBytes() const :
  if(hasSelectedText()) :
    s = qMin(selection_start_, selection_end_);
    e = qMax(selection_start_, selection_end_);

    data_.seek(s);
    return data_.read(e - s);
  }

  return QByteArray();
}

'''
// Name: selectedBytesAddress() const
'''
QHexView.address_t QHexView.selectedBytesAddress() const :
  const address_t select_base = qMin(selection_start_, selection_end_);
  return select_base + address_offset_;
}

'''
// Name: selectedBytesSize() const
'''
 QHexView.selectedBytesSize() const :

   ret;
  if(selection_end_ > selection_start_) :
    ret = selection_end_ - selection_start_;
  } else :
    ret = selection_start_ - selection_end_;
  }

  return ret;
}

'''
// Name: addressOffset() const
'''
QHexView.address_t QHexView.addressOffset() const :
  return address_offset_;
}

'''
// Name: setCommentServer(const QSharedPointer<CommentServerInterface> &p)
'''
void QHexView.setCommentServer(const QSharedPointer<CommentServerInterface> &p) :
  comment_server_ = p;
}

'''
// Name: commentServer() const
'''
QSharedPointer<QHexView.CommentServerInterface> QHexView.commentServer() const :
  return comment_server_;
}

'''
// Name: showHexDump() const
'''
bool QHexView.showHexDump() const :
  return show_hex_;
}

'''
// Name: showAddress() const
'''
bool QHexView.showAddress() const :
  return show_address_;
}

'''
// Name: showAsciiDump() const
'''
bool QHexView.showAsciiDump() const :
  return show_ascii_;
}

'''
// Name: showComments() const
'''
bool QHexView.showComments() const :
  return show_comments_;
}

'''
// Name: wordWidth() const
'''
int QHexView.wordWidth() const :
  return word_width_;
}

'''
// Name: rowWidth() const
'''
int QHexView.rowWidth() const :
  return row_width_;
}


'''
// Name: firstVisibleAddress() const
'''
QHexView.address_t QHexView.firstVisibleAddress() const :
  // current actual offset (in bytes)
  chars_per_row = bytesPerRow();
   offset = verticalScrollBar().value() * chars_per_row;

  if(origin_ != 0) :
    if(offset > 0) :
      offset += origin_;
      offset -= chars_per_row;
    }
  }

  return offset + addressOffset();
}
"""

def gui(opts):
  app = QtGui.QApplication(sys.argv)
  hexedit = QHexeditWidget(opts.file)
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
