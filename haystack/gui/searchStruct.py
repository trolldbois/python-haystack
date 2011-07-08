# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'searchStruct.ui'
#
# Created: Fri Jul  8 09:10:45 2011
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
        Search_Structure.resize(404, 385)
        self.gridLayout_2 = QtGui.QGridLayout(Search_Structure)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.gridLayout = QtGui.QGridLayout()
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.searchWidget_tree = QtGui.QTreeWidget(Search_Structure)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.searchWidget_tree.sizePolicy().hasHeightForWidth())
        self.searchWidget_tree.setSizePolicy(sizePolicy)
        self.searchWidget_tree.setBaseSize(QtCore.QSize(0, 0))
        self.searchWidget_tree.setEditTriggers(QtGui.QAbstractItemView.DoubleClicked|QtGui.QAbstractItemView.EditKeyPressed|QtGui.QAbstractItemView.SelectedClicked)
        self.searchWidget_tree.setObjectName(_fromUtf8("searchWidget_tree"))
        self.searchWidget_tree.headerItem().setText(0, _fromUtf8("1"))
        self.searchWidget_tree.header().setVisible(False)
        self.gridLayout.addWidget(self.searchWidget_tree, 3, 0, 1, 1)
        self.label = QtGui.QLabel(Search_Structure)
        self.label.setObjectName(_fromUtf8("label"))
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.lineEdit_filter = QtGui.QLineEdit(Search_Structure)
        self.lineEdit_filter.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.lineEdit_filter.setObjectName(_fromUtf8("lineEdit_filter"))
        self.gridLayout.addWidget(self.lineEdit_filter, 0, 1, 1, 1)
        self.label_2 = QtGui.QLabel(Search_Structure)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)
        self.dialog_search_structure_buttonbox = QtGui.QDialogButtonBox(Search_Structure)
        self.dialog_search_structure_buttonbox.setOrientation(QtCore.Qt.Horizontal)
        self.dialog_search_structure_buttonbox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.dialog_search_structure_buttonbox.setObjectName(_fromUtf8("dialog_search_structure_buttonbox"))
        self.gridLayout_2.addWidget(self.dialog_search_structure_buttonbox, 1, 0, 1, 1)

        self.retranslateUi(Search_Structure)
        QtCore.QObject.connect(self.dialog_search_structure_buttonbox, QtCore.SIGNAL(_fromUtf8("accepted()")), Search_Structure.accept)
        QtCore.QObject.connect(self.dialog_search_structure_buttonbox, QtCore.SIGNAL(_fromUtf8("rejected()")), Search_Structure.reject)
        QtCore.QMetaObject.connectSlotsByName(Search_Structure)

    def retranslateUi(self, Search_Structure):
        Search_Structure.setWindowTitle(QtGui.QApplication.translate("Search_Structure", "Search for a Structure", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("Search_Structure", "Structure name/Filter :", None, QtGui.QApplication.UnicodeUTF8))
        self.label_2.setText(QtGui.QApplication.translate("Search_Structure", "Registered structures :", None, QtGui.QApplication.UnicodeUTF8))

