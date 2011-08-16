# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'memmaptab.ui'
#
# Created: Mon Aug 15 23:03:05 2011
#      by: PyQt4 UI code generator 4.8.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_MemoryMappingWidget(object):
    def setupUi(self, MemoryMappingWidget):
        MemoryMappingWidget.setObjectName(_fromUtf8("MemoryMappingWidget"))
        MemoryMappingWidget.resize(1151, 528)
        self.gridLayout = QtGui.QGridLayout(MemoryMappingWidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.graphicsView = QtGui.QGraphicsView(MemoryMappingWidget)
        self.graphicsView.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.graphicsView.sizePolicy().hasHeightForWidth())
        self.graphicsView.setSizePolicy(sizePolicy)
        self.graphicsView.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.graphicsView.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.graphicsView.setObjectName(_fromUtf8("graphicsView"))
        self.gridLayout.addWidget(self.graphicsView, 0, 0, 1, 1)
        self.groupBox = QtGui.QGroupBox(MemoryMappingWidget)
        self.groupBox.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox.sizePolicy().hasHeightForWidth())
        self.groupBox.setSizePolicy(sizePolicy)
        self.groupBox.setMaximumSize(QtCore.QSize(16777215, 70))
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.show_null = QtGui.QCheckBox(self.groupBox)
        self.show_null.setGeometry(QtCore.QRect(17, 25, 125, 16))
        self.show_null.setObjectName(_fromUtf8("show_null"))
        self.show_pointers = QtGui.QCheckBox(self.groupBox)
        self.show_pointers.setGeometry(QtCore.QRect(17, 45, 125, 16))
        self.show_pointers.setObjectName(_fromUtf8("show_pointers"))
        self.gridLayout.addWidget(self.groupBox, 1, 0, 1, 1)
        self.tab_search_structures = QtGui.QToolBox(MemoryMappingWidget)
        self.tab_search_structures.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tab_search_structures.sizePolicy().hasHeightForWidth())
        self.tab_search_structures.setSizePolicy(sizePolicy)
        self.tab_search_structures.setObjectName(_fromUtf8("tab_search_structures"))
        self.page = QtGui.QWidget()
        self.page.setGeometry(QtCore.QRect(0, 0, 563, 372))
        self.page.setObjectName(_fromUtf8("page"))
        self.gridLayout_3 = QtGui.QGridLayout(self.page)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.tab_search_structures.addItem(self.page, _fromUtf8(""))
        self.page_2 = QtGui.QWidget()
        self.page_2.setGeometry(QtCore.QRect(0, 0, 563, 372))
        self.page_2.setObjectName(_fromUtf8("page_2"))
        self.tab_search_structures.addItem(self.page_2, _fromUtf8(""))
        self.gridLayout.addWidget(self.tab_search_structures, 0, 1, 1, 1)

        self.retranslateUi(MemoryMappingWidget)
        self.tab_search_structures.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MemoryMappingWidget)

    def retranslateUi(self, MemoryMappingWidget):
        MemoryMappingWidget.setWindowTitle(QtGui.QApplication.translate("MemoryMappingWidget", "Form", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox.setTitle(QtGui.QApplication.translate("MemoryMappingWidget", "Highlight", None, QtGui.QApplication.UnicodeUTF8))
        self.show_null.setText(QtGui.QApplication.translate("MemoryMappingWidget", "Null values", None, QtGui.QApplication.UnicodeUTF8))
        self.show_pointers.setText(QtGui.QApplication.translate("MemoryMappingWidget", "Pointer values", None, QtGui.QApplication.UnicodeUTF8))
        self.tab_search_structures.setItemText(self.tab_search_structures.indexOf(self.page), QtGui.QApplication.translate("MemoryMappingWidget", "Page 1", None, QtGui.QApplication.UnicodeUTF8))
        self.tab_search_structures.setItemText(self.tab_search_structures.indexOf(self.page_2), QtGui.QApplication.translate("MemoryMappingWidget", "Page 2", None, QtGui.QApplication.UnicodeUTF8))

