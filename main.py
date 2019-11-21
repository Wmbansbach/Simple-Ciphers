from PyQt5 import QtWidgets
import sys
import gui_wrapper



if __name__ == "__main__":
    application = QtWidgets.QApplication(sys.argv)
    windowObj = QtWidgets.QMainWindow()
    appWindow = gui_wrapper.Interface()
    appWindow.setupUi(windowObj)
    windowObj.show()
    sys.exit(application.exec_())
