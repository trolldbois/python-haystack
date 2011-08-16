# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'searchinfoStruct.ui'
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

class Ui_SearchInfoStructWidget(object):
    def setupUi(self, SearchInfoStructWidget):
        SearchInfoStructWidget.setObjectName(_fromUtf8("SearchInfoStructWidget"))
        SearchInfoStructWidget.resize(421, 501)
        self.gridLayout = QtGui.QGridLayout(SearchInfoStructWidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.info_listview = QtGui.QListView(SearchInfoStructWidget)
        self.info_listview.setObjectName(_fromUtf8("info_listview"))
        self.gridLayout.addWidget(self.info_listview, 0, 0, 1, 1)

        self.retranslateUi(SearchInfoStructWidget)
        QtCore.QObject.connect(self.info_listview, QtCore.SIGNAL(_fromUtf8("activated(QModelIndex)")), self.info_listview.update)
        QtCore.QMetaObject.connectSlotsByName(SearchInfoStructWidget)

    def retranslateUi(self, SearchInfoStructWidget):
        SearchInfoStructWidget.setWindowTitle(QtGui.QApplication.translate("SearchInfoStructWidget", "Form", None, QtGui.QApplication.UnicodeUTF8))

