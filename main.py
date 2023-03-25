# -*- coding:utf-8 -*-
# @FileName  :scapy_sniff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv

import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import QMainWindow, QApplication
from scapy.all import *
# from scapy_sniff import *

# 捕获总数
sniff_count = 0
# 所有捕获到的报文
sniff_array = []

class SnifferThread(QtCore.QThread):
    packet_received = QtCore.pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.paused = False

    def start_sniff(self):
        self.start()

    def stop_sniff(self):
        self.exit()

    def pause_sniff(self):
        self.paused = False

    def run(self):
        sniff(prn=self.sniff_analysis, iface=None, filter='IP', store=0)

    def sniff_analysis(self, packet):
        # now_time = datetime.now().strftime("%Y%m%d%H%M%S")
        # filename = "./email_dns_data_{0}.pcap".format(now_time)
        # # filter = 'tcp.port == 2222'
        # o_open_file = PcapWriter(filename, append=True)
        self.packet_received.emit(packet)
        # packet.show()
        # o_open_file.write(packet)


class Mainwindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()  # 渲染页面控件

    def initUI(self):
        self.setGeometry(100, 100, 1500, 1000)
        self.setWindowTitle("Packet Sniffer")

        # 整体布局为垂直布局
        self.layout = QtWidgets.QVBoxLayout()

        # 创建第一行的水平布局
        self.button_layout = QtWidgets.QHBoxLayout()
        self.start_button = QtWidgets.QPushButton("开始")
        self.pause_button = QtWidgets.QPushButton("暂停")
        self.stop_button = QtWidgets.QPushButton("停止")
        self.protocol_box = QtWidgets.QComboBox()
        self.protocol_box.addItems(['HTTP', 'TCP', 'UDP', 'IPv4', 'IPv6', 'ICMP'])

        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.pause_button)
        self.button_layout.addWidget(self.stop_button)
        self.button_layout.addWidget(self.protocol_box)

        # 创建Pacp分析区域
        col = 7
        self.packet_list_table = QtWidgets.QTableWidget()
        self.packet_list_table.setColumnCount(7)
        self.packet_list_table.setRowCount(0)
        self.packet_list_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Interactive)
        self.packet_list_table.horizontalHeader().setSectionResizeMode(6, QtWidgets.QHeaderView.Stretch)
        self.packet_list_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packet_list_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.packet_list_table.verticalHeader().setVisible(False)
        self.packet_list_table.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])

        # 创建详细分析区域
        self.analysis_layout = QtWidgets.QHBoxLayout()

        # 创建树状图
        tree = QtWidgets.QTreeWidget()
        tree.setHeaderLabels(['Name', 'Size', 'Type'])
        for i in range(2):
            parent = QtWidgets.QTreeWidgetItem(tree, ['Folder %d' % i, '', 'Folder'])
            for j in range(2):
                child = QtWidgets.QTreeWidgetItem(parent, ['File %d' % j, '10 KB', 'File'])

        tree.expandAll()

        # 创建hexdump区域
        text = QtWidgets.QTextEdit()

        self.analysis_layout.addWidget(tree)
        self.analysis_layout.addWidget(text)


        # 将布局添加到垂直布局中
        self.layout.addLayout(self.button_layout)
        self.layout.addWidget(self.packet_list_table)
        self.layout.addLayout(self.analysis_layout)

        self.setLayout(self.layout)

        # 绑定按键动作
        self.stop_sniffing_flag = False
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_received.connect(self.add_packet_to_table)

        self.start_button.clicked.connect(self.start_Action)
        self.pause_button.clicked.connect(self.pause_Action)
        self.stop_button.clicked.connect(self.stop_Action)


    def start_Action(self):
        self.stop_sniffing_flag = False
        self.start_button.setDisabled(True)
        self.stop_button.setDisabled(False)
        self.pause_button.setDisabled(False)
        self.sniffer_thread.start_sniff()

    def pause_Action(self):
        self.stop_sniffing_flag = True
        self.start_button.setDisabled(False)
        self.pause_button.setDisabled(True)
        self.sniffer_thread.pause_sniff()
        return

    def stop_Action(self):
        global sniff_array, sniff_count

        self.stop_sniffing_flag = True
        self.start_button.setDisabled(False)
        self.stop_button.setDisabled(True)
        self.sniffer_thread.stop_sniff()

        self.packet_list_table.setRowCount(0)
        sniff_count = -1
        sniff_array = []
        return

    def add_packet_to_table(self, packet):
        if self.stop_sniffing_flag:
            return

        global sniff_count, sniff_array

        sniff_count = sniff_count + 1
        sniff_array.append(packet)

        proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP', 'Ether', 'Unknown']
        proto = ''
        try:
            for pn in proto_names:
                if pn in packet:
                    proto = pn
                    break
            if proto == 'ARP' or proto == 'Ether':
                src = packet.src
                dst = packet.dst
            else:
                if 'IPv6' in packet:
                    src = packet[IPv6].src
                    dst = packet[IPv6].dst
                elif 'IP' in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
            length = len(packet)
            info = packet.summary()
        except:
            src = '0.0.0.0'
            dst = '0.0.0.0'
            proto = 'Unknown'
            length = 0
            info = '此协议暂不支持'
            print('数据分析错误')


        row_position = self.packet_list_table.rowCount()
        self.packet_list_table.insertRow(row_position)
        self.packet_list_table.setItem(row_position, 0, QtWidgets.QTableWidgetItem(str(sniff_count)))
        self.packet_list_table.setItem(row_position, 1, QtWidgets.QTableWidgetItem(str(datetime.now())))
        self.packet_list_table.setItem(row_position, 2, QtWidgets.QTableWidgetItem(str(src)))
        self.packet_list_table.setItem(row_position, 3, QtWidgets.QTableWidgetItem(str(dst)))
        self.packet_list_table.setItem(row_position, 4, QtWidgets.QTableWidgetItem(str(proto)))
        self.packet_list_table.setItem(row_position, 5, QtWidgets.QTableWidgetItem(str(length)))
        self.packet_list_table.setItem(row_position, 6, QtWidgets.QTableWidgetItem(str(info)))

    def on_click_packet_list_tree(event):
        return

# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mywindow = Mainwindow()
    mywindow.show()
    sys.exit(app.exec_())
