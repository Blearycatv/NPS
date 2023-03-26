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
class IPv4_Packet:
    def __init__(self, packet):
        # 4b 版本号
        self.version = packet.version
        # 4b 头部长度
        self.ihl = packet.ihl
        # 8b 服务类型
        self.tos = packet.tos
        # 16b 总长度
        self.total_length = packet.len
        # 16b ID
        self.id = packet.id
        self.ttl = packet.ttl
        self.protocol = packet.proto
        self.src_ip = packet.src
        self.dst_ip = packet.dst
        self.flags = packet.flags
        self.frag = packet.frag
        self.chksum = packet.chksum
        self.payload = packet.payload

    def get_version(self):
        return f"IP Version: {self.version}"

    def get_ihl(self):
        return f"IP Header Length: {self.ihl} bytes"

    def get_tos(self):
        return f"Type of Service: {self.tos}"

    def get_ttl(self):
        return f"Time to Live: {self.ttl}"

    def get_protocol(self):
        return f"Protocol: {self.protocol}"

    def get_src_ip(self):
        return f"Source IP Address: {self.src_ip}"

    def get_dst_ip(self):
        return f"Destination IP Address: {self.dst_ip}"

    def get_total_length(self):
        return f"Total Length: {self.total_length} bytes"

    def get_id(self):
        return f"Identification: {self.id}"

    def get_flags(self):
        return f"Flags: {self.flags}"

    def get_frag(self):
        return f"Fragment Offset: {self.frag}"

    def get_chksum(self):
        return f"Header Checksum: {hex(self.chksum)}"

    def get_payload(self):
        return f"Payload: {self.payload.hex()}"

    def __str__(self):
        return self.payload.hex()

class Ethernet_Packet:
    def __init__(self, packet):
        # 前六个字节
        self.dst_mac = packet.dst
        # 7-12字节
        self.src_mac = packet.src
        # 13-14字节
        if packet.type == 0x0800:
            self.ethertype = 'IP'
        elif packet.type == 0x0806:
            self.ethertype = 'ARP'
        elif packet.type == 0x86DD:
            self.ethertype = 'IPv6'
        else:
            self.ethertype = 'Unkonw'

    def print_dst_mac(self):
        return f"Destination MAC Address: {self.dst_mac}"

    def print_src_mac(self):
        return f"Source MAC Address: {self.src_mac}"

    def print_ethertype(self):
        return f"EtherType: {self.ethertype}"

class UDP_Packet:
    def __init__(self, frame_str):
        frame = Ether(frame_str)
        self.src_port = frame.payload.sport
        self.dst_port = frame.payload.dport
        self.length = frame.payload.len
        self.checksum = frame.payload.chksum
        self.payload = frame.payload.payload

    def print_src_port(self):
        return f"Source Port: {self.src_port}"

    def print_dst_port(self):
        return f"Destination Port: {self.dst_port}"

    def print_length(self):
        return f"Length: {self.length}"

    def print_checksum(self):
        return f"Checksum: {hex(self.checksum)}"

    def print_payload(self):
        return f"Payload: {self.payload.hex()}"

    def __str__(self):
        return self.payload.hex()

class IPv6_Packet:
    def __init__(self, packet):
        self.version = packet.version
        self.traffic_class = packet.tc
        self.flow_label = packet.fl
        self.payload_length = packet.plen
        self.next_header = packet.nh
        self.hop_limit = packet.hlim
        self.source_address = packet.src
        self.destination_address = packet.dst

class TCP_Packet:
    def __init__(self, packet_str):
        packet = TCP(packet_str)
        self.src_port = packet.sport
        self.dst_port = packet.dport
        self.seq_num = packet.seq
        self.ack_num = packet.ack
        self.header_len = packet.dataofs * 4
        self.flags = packet.flags
        self.window_size = packet.window
        self.checksum = packet.chksum
        self.urgent_pointer = packet.urgptr
        self.payload = packet.payload

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port

    def get_seq_num(self):
        return self.seq_num

    def get_ack_num(self):
        return self.ack_num

    def get_header_len(self):
        return self.header_len

    def get_flags(self):
        return self.flags

    def get_window_size(self):
        return self.window_size

    def get_checksum(self):
        return self.checksum

    def get_urgent_pointer(self):
        return self.urgent_pointer

    def get_payload(self):
        return self.payload

    def __str__(self):
        return self.payload.hex()




if __name__ == "__main__":

    def callback(packet):
        ether = Ethernet_Packet(packet['Ether'])

        print(ether.ethertype)

    packet = sniff(offline='wireshark.pcap', count=1, prn=callback)


    # packet_producer()

