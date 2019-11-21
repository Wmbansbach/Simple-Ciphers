from PyQt5.QtGui import *
from PyQt5 import QtWidgets
from functools import partial

import msgbox
import transposition
import substitution
import gui
from standard_crypto import Encryption
from standard_crypto import Hashes



class Interface(gui.Ui_MainWindow):
    """ Wrapper Class for PyQt Window script

        Contains methods for events driven by
        GUI buttons
    """
    def __init__(self):
        super(Interface, self).__init__()
        self.sym_mode = bool
        self.digester = Hashes()

    def Finish_Ui(self):
        self.label.setVisible(False) #
        self.lineEdit.setVisible(False) #
        self.pushButton_2.clicked.connect(self.D_Ingress) #
        self.pushButton.clicked.connect(self.E_Ingress) #
        self.pushButton_3.clicked.connect(self.switch)
        self.pushButton_3.setToolTip("Flip the values of the two fields")
        self.pushButton_4.clicked.connect(self.reset)
        self.pushButton_4.setToolTip("Reset all fields")
        self.actionSHA_1.triggered.connect(partial(self.runHash, "sha1"))
        self.actionSHA_256.triggered.connect(partial(self.runHash, "sha256"))
        self.actionSHA_512.triggered.connect(partial(self.runHash, "sha512"))
        self.actionMD5.triggered.connect(partial(self.runHash, "md5"))
        self.actionAES.triggered.connect(self.setAES)
        self.radioButton_1.toggled.connect(self.keyControl)
        self.radioButton_2.toggled.connect(self.keyControl)
        self.radioButton_3.toggled.connect(self.keyControl)
        self.radioButton_4.toggled.connect(self.keyControl)
        self.radioButton_5.toggled.connect(self.keyControl)
        self.radioButton_5.setToolTip("Three Position Shift Polyalphabetic Cipher")
        self.radioButton_4.setToolTip("Transposition Cipher")
        self.radioButton_3.setToolTip("Three Position Shift Monoalphabetic Cipher")
        self.radioButton_1.setToolTip("Polyalphabetic Vigenere Square Cipher")
        self.radioButton_2.setToolTip("Boolean Cipher")

        self.group = QtWidgets.QButtonGroup()
        self.group.addButton(self.radioButton_1)
        self.group.addButton(self.radioButton_2)
        self.group.addButton(self.radioButton_3) 
        self.group.addButton(self.radioButton_4) 
        self.group.addButton(self.radioButton_5)

        self.ciphers = { 4 : transposition.XPC(),
                         3 : substitution.TPSMC(),
                         5 : substitution.TPSPC(),
                         1 : substitution.PVSC(),
                         2 : transposition.XOR() }
        
    def E_Ingress(self):
        selection = self.checkRadio()
        msg = self.plainTextEdit.toPlainText()
        key = self.lineEdit.text()
        if self.validate() and self.sym_mode:
            esuite = Encryption()
            self.textEdit.setPlainText(esuite.AES(True, bytes(msg, "utf-8"), bytes(key, "utf-8")))
        else:
            cipher = self.ciphers[selection]
            if selection == 2 or selection == 1: 
                self.textEdit.setText(cipher.process(1, msg, key))
            else:
                self.textEdit.setText(cipher.process(1, msg))
        self.plainTextEdit.setPlainText("")

        
    def D_Ingress(self):
        selection = self.checkRadio()
        msg = self.plainTextEdit.toPlainText()
        key = self.lineEdit.text()

        if self.validate() and self.sym_mode:
            esuite = Encryption()
            self.textEdit.setPlainText(esuite.AES(False, bytes(msg, "utf-8"), bytes(key, "utf-8")))
        else:
            cipher = self.ciphers[selection]
            if selection == 2 or selection == 1: 
                self.textEdit.setText(cipher.process(0, msg, key))
            else:
                self.textEdit.setText(cipher.process(0, msg))
        self.plainTextEdit.setPlainText("")

    def validate(self):
        if self.plainTextEdit.toPlainText() == "":
            msgbox.App("Whoops","Please ensure you have input a message.")
            return False
        else:
            return True
    
    def keyControl(self):
        self.label_6.setHidden(False)
        self.label_4.setHidden(True)
        self.sym_mode = False

        sel = self.checkRadio()
        if sel == 1 or sel == 2 or not self.label.isVisible:
            self.label.setVisible(True) #
            self.lineEdit.setVisible(True) #
            self.label.setText("Key:")
        else:
            self.label.setVisible(False) #
            self.lineEdit.setVisible(False) #
            self.lineEdit.setText("")
            
    def checkRadio(self):
        for i in range(1,6):
            rc = eval("self.radioButton_" + str(i) + ".isChecked()")
            if rc:
                return i
        return 0

    def runHash(self, alg):
        if self.validate():
            self.digester.setHash(self.plainTextEdit.toPlainText(), alg)

    def setAES(self):
        self.reset()
        self.label.setVisible(True) #
        self.lineEdit.setVisible(True) #
        self.sym_mode = True
        self.label.setText("Password:")
        self.label_4.setHidden(False)
        
    def switch(self):
        self.plainTextEdit.setPlainText(self.textEdit.toPlainText())
        self.textEdit.setPlainText("")

    def reset(self):
        self.plainTextEdit.setPlainText("")
        self.textEdit.setPlainText("")
        self.label.setVisible(False) #
        self.lineEdit.setVisible(False) #
        self.lineEdit.setText("")
        self.group.setExclusive(False)
        self.radioButton_1.setChecked(False)
        self.radioButton_2.setChecked(False)
        self.radioButton_3.setChecked(False)
        self.radioButton_4.setChecked(False)
        self.radioButton_5.setChecked(False)
        self.group.setExclusive(True)
        self.label_4.setHidden(True)
        self.label_6.setHidden(True)
        
