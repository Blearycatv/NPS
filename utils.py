# -*- coding:utf-8 -*-
# @FileName  :utils.py
# @Time      :2023/3/15 20:48
# @Author    :Blearycatv

from scapy.all import *

def ip_analysis(IP_data):
    return

def get_NIC():
    nic_dic = get_windows_if_list()
    nic_key = nic_dic[0].keys()

    print(nic_key)


if __name__ == "__main__":
    get_NIC()
    run_code = 0
