from PyQt5.QtWidgets import QWidget, QMessageBox
import sys


class App(QWidget):
 
    def __init__(self, title, msg=""):
        super().__init__()
        self.msg = msg
        self.title = title
        self.initUI()

    def initUI(self):
        QMessageBox.information(self, self.title, self.msg, QMessageBox.Ok)

 
        