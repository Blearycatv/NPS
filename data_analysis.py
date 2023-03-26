# -*- coding:utf-8 -*-
# @FileName  :data_analysis.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv
import time

from scapy.all import *
import time
import threading
import binascii


# IP数据帧分析
def IPv4_Packet(packet):
    IPDatagram = {}
    packet = bytes(packet['IP'])
    # 根据RFC791协议对数据包进行解析
    IPDatagram['version'] = packet[0] >> 4
    IPDatagram['headLength'] = packet[0] & 0x0f
    IPDatagram['serviceType'] = packet[1]
    IPDatagram['totalLength'] = (packet[2] << 8) + packet[3]
    IPDatagram['identification'] = (packet[4] << 8) + packet[5]
    IPDatagram['flag'] = packet[6] >> 5
    IPDatagram['moreFragment'] = IPDatagram['flag'] & 1
    IPDatagram['dontFragment'] = (IPDatagram['flag'] >> 1) & 1
    IPDatagram['fragmentOffset'] = ((packet[6] & 0x1f) << 8) + packet[7]
    IPDatagram['TTL'] = packet[8]
    IPDatagram['protocol'] = packet[9]
    IPDatagram['headerCheckSum'] = (packet[10] << 8) + packet[11]
    # 源IP地址和目的IP地址都按照IP地址的格式用字符串存储
    IPDatagram['sourceAddress'] = "%d.%d.%d.%d" % (packet[12], packet[13], packet[14], packet[15])
    IPDatagram['destinationAddress'] = "%d.%d.%d.%d" % (packet[16], packet[17], packet[18], packet[19])
    # 根据数据包中头部长度确定是否有选项，如果有则添加至option列表中
    IPDatagram['options'] = []
    if IPDatagram['headLength'] > 5:
        step = 5
        while step < IPDatagram['headLength']:
            IPDatagram['options'].append(packet[step * 4])
            IPDatagram['options'].append(packet[step * 4 + 1])
            IPDatagram['options'].append(packet[step * 4 + 2])
            IPDatagram['options'].append(packet[step * 4 + 3])
            step += 1
    # 根据数据包中的总长度将数据部分添加至data列表中
    IPDatagram['data'] = ''
    step = IPDatagram['headLength'] * 4
    while step < IPDatagram['totalLength']:
        IPDatagram['data'] = IPDatagram['data'] + str(packet[step])
        step += 1
    # 返回储存有数据包数据的字典
    return IPDatagram

def Ethernet_Packet(packet):

    EthDatagram = {}
    packet = bytes(packet['Ethernet'])

    EthDatagram['sourceAddress'] = "%d.%d.%d.%d.%d.%d" % (packet[0], packet[1], packet[2], packet[3], packet[4], packet[5])
    EthDatagram['destinationAddress'] = "%d.%d.%d.%d.%d.%d" % (packet[6], packet[7], packet[8], packet[9], packet[10], packet[11])
    EthDatagram['type'] = packet[12] << 8 | packet[13]

    return EthDatagram
def UDP_Packet(packet):
    UDPDatagram = {}
    packet = bytes(packet['UDP'])

    UDPDatagram['SourcePort'] = packet[0] << 8 | packet[1]
    UDPDatagram['DestinationPort'] = packet[2] << 8 | packet[3]
    UDPDatagram['length'] = packet[4]* 256 + packet[5]
    UDPDatagram['Chexksum'] = packet[6] << 8 | packet[7]
    UDPDatagram['data'] = ''
    step = 9
    while step < UDPDatagram['length']:
        UDPDatagram['data'] = UDPDatagram['data'] + str(packet[step])
        step += 1

    return UDPDatagram
def IPv6_Packet(packet):
    IPv6Datagram = {}
    packet = bytes(packet['IPv6'])

    IPv6Datagram['Version'] = packet[0] >> 4
    IPv6Datagram['TrafficClass'] = (packet[0] & 0x0F) << 4 | (packet[1] >> 4)
    IPv6Datagram['FlowLabel'] = (packet[1] & 0x0F) << 16 | packet[2] << 8 | packet[3]
    IPv6Datagram['PayloadLength'] = packet[4] << 8 | packet[5]
    IPv6Datagram['NextHeader'] = packet[6]
    IPv6Datagram['HopLimit'] = packet[7]
    IPv6Datagram['SourceAddress'] = ':'.join('{:02x}'.format(packet[i:i+2][0]) + '{:02x}'.format(packet[i:i+2][1]) for i in range(8, 24, 2))
    IPv6Datagram['DestinationAddress'] = ':'.join('{:02x}'.format(packet[i:i+2][0]) + '{:02x}'.format(packet[i:i+2][1]) for i in range(24, 40, 2))
    IPv6Datagram['Payload'] = packet[40:]

    return IPv6Datagram


def TCP_Packet(packet):
    TCPDatagram = {}
    packet = bytes(packet['TCP'])

    TCPDatagram['SourcePort'] = packet[0] << 8 | packet[1]
    TCPDatagram['DestinationPort'] = packet[2] << 8 | packet[3]
    TCPDatagram['SequenceNumber'] = packet[4] << 24 | packet[5] << 16 | packet[6] << 8 | packet[7]
    TCPDatagram['AcknowledgmentNumber'] = packet[8] << 24 | packet[9] << 16 | packet[10] << 8 | packet[11]
    TCPDatagram['DataOffset'] = packet[12] >> 4
    TCPDatagram['Reserved'] = (packet[12] & 0x0F) >> 1
    TCPDatagram['NS'] = packet[12] & 0x01
    TCPDatagram['CWR'] = packet[13] & 0x80
    TCPDatagram['ECE'] = packet[13] & 0x40
    TCPDatagram['URG'] = packet[13] & 0x20
    TCPDatagram['ACK'] = packet[13] & 0x10
    TCPDatagram['PSH'] = packet[13] & 0x08
    TCPDatagram['RST'] = packet[13] & 0x04
    TCPDatagram['SYN'] = packet[13] & 0x02
    TCPDatagram['FIN'] = packet[13] & 0x01
    TCPDatagram['Window'] = packet[14] << 8 | packet[15]
    TCPDatagram['Checksum'] = packet[16] << 8 | packet[17]
    TCPDatagram['UrgentPointer'] = packet[18] << 8 | packet[19]
    TCPDatagram['Options'] = ''
    step = 20
    while step < TCPDatagram['DataOffset'] * 4:
        TCPDatagram['Options'] = TCPDatagram['Options'] + str(packet[step])
        step += 1
    TCPDatagram['Data'] = ''
    while step < len(packet):
        TCPDatagram['Data'] = TCPDatagram['Data'] + str(packet[step])
        step += 1

    return TCPDatagram

def ARP_Packet(packet):
    ARPDatagram = {}
    packet = bytes(packet['ARP'])

    ARPDatagram['HardwareType'] = packet[0] << 8 | packet[1]
    ARPDatagram['ProtocolType'] = packet[2] << 8 | packet[3]
    ARPDatagram['HardwareSize'] = packet[4]
    ARPDatagram['ProtocolSize'] = packet[5]
    ARPDatagram['Opcode'] = packet[6] << 8 | packet[7]
    ARPDatagram['SenderMACAddress'] = ':'.join('{:02x}'.format(packet[i]) for i in range(8, 14))
    ARPDatagram['SenderIPAddress'] = '.'.join(str(packet[i]) for i in range(14, 18))
    ARPDatagram['TargetMACAddress'] = ':'.join('{:02x}'.format(packet[i]) for i in range(18, 24))
    ARPDatagram['TargetIPAddress'] = '.'.join(str(packet[i]) for i in range(24, 28))

    return ARPDatagram



if __name__ == "__main__":
    packets = sniff(count=1, filter='arp', prn=ARP_Packet)
    packets[0].show()

