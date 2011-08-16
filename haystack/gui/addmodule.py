# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'addmodule.ui'
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

class Ui_addModuleDialog(object):
    def setupUi(self, addModuleDialog):
        addModuleDialog.setObjectName(_fromUtf8("addModuleDialog"))
        addModuleDialog.setWindowModality(QtCore.Qt.ApplicationModal)
        addModuleDialog.resize(394, 110)
        addModuleDialog.setSizeGripEnabled(False)
        addModuleDialog.setModal(True)
        self.gridLayout = QtGui.QGridLayout(addModuleDialog)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.label = QtGui.QLabel(addModuleDialog)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout.addWidget(self.label)
        self.lineEdit = QtGui.QLineEdit(addModuleDialog)
        self.lineEdit.setObjectName(_fromUtf8("lineEdit"))
        self.horizontalLayout.addWidget(self.lineEdit)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        self.buttonBox = QtGui.QDialogButtonBox(addModuleDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(addModuleDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), addModuleDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), addModuleDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(addModuleDialog)

    def retranslateUi(self, addModuleDialog):
        addModuleDialog.setWindowTitle(QtGui.QApplication.translate("addModuleDialog", "Dialog", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("addModuleDialog", "Module name", None, QtGui.QApplication.UnicodeUTF8))

