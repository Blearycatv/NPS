# -*- coding:utf-8 -*-
# @FileName  :scapy_sniff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv

import sys
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication


class Mainwindow(QMainWindow):
    def __init__(self):
        super(QMainWindow, self).__init__()
        self.initUI()  # 渲染页面控件

    def initUI(self):

        filemenu =self.menuBar()

        # 创建基础功能选项
        start_sniff = QtWidgets.QAction('Start', self)
        end_sniff = QtWidgets.QAction('End', self)
        restart_sniff = QtWidgets.QAction('Restart', self)

        # 创建可选协议类型
        protocol = QtWidgets.QMenu('Protocol_select', self)
        tcp_pro = QtWidgets.QAction('TCP', self)
        IP_pro = QtWidgets.QAction('IP', self)
        tcp_pro.setCheckable(True)
        tcp_pro.setChecked(True)
        IP_pro.setCheckable(True)

        pro_item = QtWidgets.QActionGroup(self)
        pro_item.addAction(tcp_pro)
        pro_item.addAction(IP_pro)
        pro_item.setExclusive(True)

        protocol.addAction(tcp_pro)
        protocol.addAction(IP_pro)

        filemenu.addAction(start_sniff)
        filemenu.addAction(end_sniff)
        filemenu.addAction(restart_sniff)
        filemenu.addMenu(protocol)

        # 出现位置待优化
        self.setGeometry(700, 300, 1200, 800)
        self.setWindowTitle('MySniff')
        self.show()


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':

    app = QApplication(sys.argv)
    mywindow = Mainwindow()
    mywindow.show()
    sys.exit(app.exec_())
