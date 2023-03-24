# -*- coding:utf-8 -*-
# @FileName  :scapy_sniff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv

import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import QMainWindow, QApplication
import scapy_sniff


class Mainwindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()  # 渲染页面控件

    def initUI(self):
        self.setWindowTitle("MySniff")
        self.resize(1500, 1000)

        # 整体布局为垂直布局
        layout = QtWidgets.QVBoxLayout()

        # 创建第一行的水平布局
        button_layout = QtWidgets.QHBoxLayout()
        start_button = QtWidgets.QPushButton("开始")
        pause_button = QtWidgets.QPushButton("暂停")
        stop_button = QtWidgets.QPushButton("停止")
        button_layout.addWidget(start_button)
        button_layout.addWidget(pause_button)
        button_layout.addWidget(stop_button)

        # 创建Pacp分析区域
        col = 7
        packet_list_table = QtWidgets.QTableWidget()
        packet_list_table.setColumnCount(7)
        packet_list_table.setRowCount(20)
        packet_list_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        packet_list_table.horizontalHeader().setSectionResizeMode(6, QtWidgets.QHeaderView.Stretch)
        packet_list_table.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        # 创建详细分析区域

        analysis_layout = QtWidgets.QHBoxLayout()

        # 创建树状图
        tree = QtWidgets.QTreeWidget()
        tree.setHeaderLabels(['Name', 'Size', 'Type'])
        for i in range(5):
            parent = QtWidgets.QTreeWidgetItem(tree, ['Folder %d' % i, '', 'Folder'])
            for j in range(3):
                child = QtWidgets.QTreeWidgetItem(parent, ['File %d' % j, '10 KB', 'File'])

        tree.expandAll()

        # 创建十六进制数区域
        text = QtWidgets.QTextEdit()


        analysis_layout.addWidget(tree)
        analysis_layout.addWidget(text)

        # 创建16进制输出区域

        # 将布局添加到垂直布局中
        layout.addLayout(button_layout)
        layout.addWidget(packet_list_table)
        layout.addLayout(analysis_layout)

        self.setLayout(layout)


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':

    app = QApplication(sys.argv)
    mywindow = Mainwindow()
    mywindow.show()
    sys.exit(app.exec_())
