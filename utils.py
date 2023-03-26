# -*- coding:utf-8 -*-
# @FileName  :utils.py
# @Time      :2023/3/15 20:48
# @Author    :Blearycatv

from scapy.all import *

def ip_analysis(IP_data):
    return

def get_NIC():
    nic_dic = get_windows_if_list()
    nic = []

    for i in nic_dic:
        nic.append(i['description'])

    return nic


if __name__ == "__main__":
    print(get_NIC())
    run_code = 0
