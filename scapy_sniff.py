# -*- coding:utf-8 -*-
# @FileName  :scapy_sniff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv
import time

from scapy.all import *
import time
import threading

stop_sniff_event = threading.Event()
pause_sniff_event = threading.Event()

# 捕获总数
sniff_count = 0
# 所有捕获到的报文
sniff_array = []

pcapdata = {
        'number': 0,
        'startime': 0.0,
        'endtime': 0.0,
        '_time': 0.0,
        'source': "0.0.0.0",
        'destination': "0.0.0.0",
        'protocol': "",
        'len': 0,
        'info': None
    }

# 数据包捕获和显示
def packet_producer():
    sniff(prn=sniff_analysis, iface=None, filter='tcp', offline='wireshark.pcap', count=1)
    return

def sniff_analysis(packet):
    count = 2

    # now_time = datetime.now().strftime("%Y%m%d%H%M%S")
    # filename = "./email_dns_data_{0}.pcap".format(now_time)
    # # filter = 'tcp.port == 2222'
    # o_open_file = PcapWriter(filename, append=True)

    global pcapdata, sniff_count, sniff_array

    # if (pcapdata['number'] == 0):
    #     pcapdata['startime'] = time.time()

    sniff_count = sniff_count + 1
    sniff_array.append(packet)
    # pcapdata['number'] = pcapdata['number'] + 1
    # pcapdata['endtime'] = time.time()
    # pcapdata['_time'] = pcapdata['endtime'] - pcapdata['startime']
    # pcapdata['source'] = packet['IP'].src
    # pcapdata['destination'] = packet['IP'].dst
    # pcapdata['protocol'] = packet['IP'].proto
    # pcapdata['len'] = len(packet)
    # pcapdata['info'] = packet['Raw'].load

    print(packet)
    # print(packet['IP'].proto)

    # packet.show()
    # o_open_file.write(packet)
    # print(type(packet))

if __name__ == "__main__":
    # packet_producer()
    data = sniff(iface="Intel(R) Ethernet Connection (16) I219-LM", count=1, filter='tcp', prn=sniff_analysis)
    print(data)
