# -*- coding:utf-8 -*-
# @FileName  :scapy_sniff.py
# @Time      :2023/3/20 13:40
# @Author    :Blearycatv
import time

from scapy.all import *
import time

global pcapdata

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

def sniff_analysis():
    count = 2

    # now_time = datetime.now().strftime("%Y%m%d%H%M%S")
    # filename = "./email_dns_data_{0}.pcap".format(now_time)
    # # filter = 'tcp.port == 2222'
    # o_open_file = PcapWriter(filename, append=True)

    def callback(packet):

        global pcapdata

        if (pcapdata['number'] == 0):
            pcapdata['startime'] = time.time()

        pcapdata['number'] = pcapdata['number'] + 1
        pcapdata['endtime'] = time.time()
        pcapdata['_time'] = pcapdata['endtime'] - pcapdata['startime']
        pcapdata['source'] = packet['IP'].src
        pcapdata['destination'] = packet['IP'].dst
        pcapdata['protocol'] = packet['IP'].proto
        pcapdata['len'] = len(packet)
        pcapdata['info'] = packet[Raw].load

        print(pcapdata)
        print(packet['IP'].proto)

        # packet.show()
        # o_open_file.write(packet)
        # print(type(packet))

    dpkt_input = sniff(offline='wireshark.pcap', count=count, filter=None, prn=callback)
    print(dpkt_input)


if __name__ == "__main__":
    sniff_analysis()
    # data = sniff(iface="Intel(R) Ethernet Connection (16) I219-LM", count=1, filter='tcp', prn=callback, )
    # print(data)
