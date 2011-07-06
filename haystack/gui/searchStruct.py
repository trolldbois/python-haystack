# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'searchStruct.ui'
#
# Created: Wed Jul  6 13:45:26 2011
#      by: PyQt4 UI code generator 4.8.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_Search_Structure(object):
    def setupUi(self, Search_Structure):
        Search_Structure.setObjectName(_fromUtf8("Search_Structure"))
        Search_Structure.resize(404, 300)
        self.dialog_search_structure_buttonbox = QtGui.QDialogButtonBox(Search_Structure)
        self.dialog_search_structure_buttonbox.setGeometry(QtCore.QRect(30, 240, 341, 32))
        self.dialog_search_structure_buttonbox.setOrientation(QtCore.Qt.Horizontal)
        self.dialog_search_structure_buttonbox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.dialog_search_structure_buttonbox.setObjectName(_fromUtf8("dialog_search_structure_buttonbox"))
        self.gridLayoutWidget = QtGui.QWidget(Search_Structure)
        self.gridLayoutWidget.setGeometry(QtCore.QRect(0, 10, 401, 221))
        self.gridLayoutWidget.setObjectName(_fromUtf8("gridLayoutWidget"))
        self.gridLayout = QtGui.QGridLayout(self.gridLayoutWidget)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.treeView = QtGui.QTreeView(self.gridLayoutWidget)
        self.treeView.setObjectName(_fromUtf8("treeView"))
        self.gridLayout.addWidget(self.treeView, 0, 0, 1, 1)

        self.retranslateUi(Search_Structure)
        QtCore.QObject.connect(self.dialog_search_structure_buttonbox, QtCore.SIGNAL(_fromUtf8("accepted()")), Search_Structure.accept)
        QtCore.QObject.connect(self.dialog_search_structure_buttonbox, QtCore.SIGNAL(_fromUtf8("rejected()")), Search_Structure.reject)
        QtCore.QMetaObject.connectSlotsByName(Search_Structure)

    def retranslateUi(self, Search_Structure):
        Search_Structure.setWindowTitle(QtGui.QApplication.translate("Search_Structure", "Search for a Structure", None, QtGui.QApplication.UnicodeUTF8))

