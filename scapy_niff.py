# -*- coding:utf-8 -*-
# @FileName  :scapy_niff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv

from scapy.all import *

if __name__ == "__main__":
    count = input("Input catch tcp num:")
    now_time = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = "./email_dns_data_{0}.pcap".format(now_time)
    # filter = 'tcp.port == 2222'
    o_open_file = PcapWriter(filename, append=True)


    def callback(packet):
        packet.show()
        o_open_file.write(packet)


    dpkt_input = sniff(iface="Intel(R) Wi-Fi 6 AX201 160MHz", count=int(count), filter='tcp', prn=callback)
