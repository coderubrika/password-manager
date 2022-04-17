# здесь будет храниться ядро работы ui

"""
давай обсудим как это должно быть в итоге

будет нечто, куда передается главное окно из другой части программы и функционал для вызова
окон из пути откуда

мне нравится этот план

для простоты пока сами создадим окно (потом можно поэксперементировать с друмими ui фрейформами)
https://www.youtube.com/watch?v=82v2ZR-g6wY&ab_channel=AlanDMooreCodes обязательно к просмотру
"""

from PyQt5 import QtWidgets, QtCore

class MainWindow(QtWidgets.QWidget):

    def __init__(self, parent=None):
        QtWidgets.QWidget.__init__(self, parent)

if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.setWindowTitle("Main window")
    window.resize(480, 200)
    window.show()
    sys.exit(app.exec_())