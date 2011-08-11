# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'searchinfoStruct.ui'
#
# Created: Wed Aug 10 23:48:55 2011
#      by: PyQt4 UI code generator 4.8.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_SearchInfoStructWidget(object):
    def setupUi(self, SearchInfoStructWidget):
        SearchInfoStructWidget.setObjectName(_fromUtf8("SearchInfoStructWidget"))
        SearchInfoStructWidget.resize(421, 501)
        self.gridLayout = QtGui.QGridLayout(SearchInfoStructWidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.info_tableview = QtGui.QTableView(SearchInfoStructWidget)
        self.info_tableview.setObjectName(_fromUtf8("info_tableview"))
        self.gridLayout.addWidget(self.info_tableview, 2, 0, 1, 1)
        self.info_listview = QtGui.QListView(SearchInfoStructWidget)
        self.info_listview.setObjectName(_fromUtf8("info_listview"))
        self.gridLayout.addWidget(self.info_listview, 0, 0, 1, 1)
        spacerItem = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 1, 0, 1, 1)

        self.retranslateUi(SearchInfoStructWidget)
        QtCore.QMetaObject.connectSlotsByName(SearchInfoStructWidget)

    def retranslateUi(self, SearchInfoStructWidget):
        SearchInfoStructWidget.setWindowTitle(QtGui.QApplication.translate("SearchInfoStructWidget", "Form", None, QtGui.QApplication.UnicodeUTF8))

