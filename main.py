# -*- coding:utf-8 -*-
# @FileName  :data_analysis.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv

import sys
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import QMainWindow, QApplication
from scapy.all import *
from data_analysis import IPv4_Packet, Ethernet_Packet, UDP_Packet, TCP_Packet,IPv6_Packet,ARP_Packet

# 捕获总数
sniff_count = 0
# 所有捕获到的报文
sniff_array = []

class SnifferThread(QtCore.QThread):
    packet_received = QtCore.pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.paused = False
        self.filter = ''
        self.iface = None

    def start_sniff(self, filter, iface):
        self.filter = filter

        if iface == '':
            self.iface = None
        else:
            self.iface = iface
        self.start()

    def stop_sniff(self):
        self.filter = ''
        self.iface = None
        self.terminate()

    def pause_sniff(self):
        self.exit()

    def run(self):
        sniff(prn=self.sniff_analysis, iface=self.iface, filter=self.filter, store=0)

    def sniff_analysis(self, packet):
        self.packet_received.emit(packet)


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
        self.netcard = QtWidgets.QComboBox()
        self.netcard.addItems([''] + self.get_NIC())
        self.protocol_box = QtWidgets.QComboBox()
        self.protocol_box.addItems(['', 'tcp', 'udp', 'ip', 'ip6', 'icmp', 'arp'])

        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.pause_button)
        self.button_layout.addWidget(self.stop_button)
        self.button_layout.addWidget(self.netcard)
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
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderHidden(True)

        # 创建hexdump区域
        self.text = QtWidgets.QTextEdit()
        self.text.setReadOnly(True)

        self.analysis_layout.addWidget(self.tree)
        self.analysis_layout.addWidget(self.text)


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
        self.packet_list_table.itemClicked.connect(self.on_click_packet_list_tree)


    def start_Action(self):
        self.stop_sniffing_flag = False
        self.start_button.setDisabled(True)
        self.stop_button.setDisabled(False)
        self.pause_button.setDisabled(False)
        self.netcard.setDisabled(True)
        self.protocol_box.setDisabled(True)

        filter_data = self.protocol_box.currentText()
        netcard_data = self.netcard.currentText()

        self.sniffer_thread.start_sniff(filter=filter_data, iface=netcard_data)

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
        self.netcard.setDisabled(False)
        self.protocol_box.setDisabled(False)
        self.sniffer_thread.stop_sniff()

        self.packet_list_table.setRowCount(0)
        sniff_count = 0
        sniff_array = []

        return

    def add_packet_to_table(self, packet):

        if self.stop_sniffing_flag:
            return

        global sniff_count, sniff_array

        sniff_count = sniff_count + 1
        sniff_array.append(packet)

        proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP',  'Ether', 'Unknown']
        proto = ''
        try:
            for pn in proto_names:
                if pn in packet:
                    proto = pn
                    break

            if proto == 'ARP' or proto ==  'Ether':
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

    def on_click_packet_list_tree(self, item):
        row = item.row()

        number = int(self.packet_list_table.item(row, 0).text()) - 1
        packet_data = sniff_array[int(number)]

        hextext = hexdump(packet_data,  dump=True)
        self.text.setText(hextext)
        self.display_in_tree(packet_data)
        return

    def display_in_tree(self, packet):

        self.tree.clear()

        lines = (packet.show(dump=True)).split('\n')
        last_tree_entry = None
        for line in lines:
            if line.startswith('#'):
                line = line.strip('# ')
                last_tree_entry = QtWidgets.QTreeWidgetItem(self.tree)

                if line == '[ Ethernet ]':
                    last_tree_entry.setText(0, '以太网帧：')
                    Ethdata = Ethernet_Packet(packet)
                    for key in Ethdata.keys():
                        strdata = str(key) +': ' + str(Ethdata[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue
                elif line == '[ IP ]':
                    last_tree_entry.setText(0, 'IP数据帧：')
                    IPdata = IPv4_Packet(packet)
                    for key in IPdata.keys():
                        strdata = str(key) +': ' + str(IPdata[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue

                elif line == '[ UDP ]':
                    last_tree_entry.setText(0, 'UDP数据帧：')
                    UDPdata = UDP_Packet(packet)
                    for key in UDPdata.keys():
                        strdata = str(key) +': ' + str(UDPdata[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue
                elif line == '[ TCP ]':
                    last_tree_entry.setText(0, 'TCP数据帧：')
                    TCPdata = TCP_Packet(packet)
                    for key in TCPdata.keys():
                        strdata = str(key) +': ' + str(TCPdata[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue
                elif line == '[ IPv6 ]':
                    last_tree_entry.setText(0, 'IPv6数据帧：')
                    IP6data = IPv6_Packet(packet)
                    for key in IP6data.keys():
                        strdata = str(key) +': ' + str(IP6data[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue
                elif line == '[ ARP ]':
                    last_tree_entry.setText(0, 'ARP数据帧：')
                    ARPdata = ARP_Packet(packet)
                    for key in ARPdata.keys():
                        strdata = str(key) +': ' + str(ARPdata[key])
                        child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                        child.setText(0, strdata)
                    last_tree_entry = None
                    continue
                else:
                    last_tree_entry.setText(0, line)

            else:
                child = QtWidgets.QTreeWidgetItem(last_tree_entry)
                child.setText(0, line)

    def get_NIC(self):
        nic_dic = get_windows_if_list()
        nic = []

        for i in nic_dic:
            nic.append(i['description'])

        return nic

# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    app = QApplication(sys.argv)
    mywindow = Mainwindow()
    mywindow.show()
    sys.exit(app.exec_())
