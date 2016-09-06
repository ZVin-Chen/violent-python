#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *


def pktPrint(pkt):
    if pkt.haslayer(Dot11Beacon):
        print '[+] Detected 802.11 Beacon Frame'
    elif pkt.haslayer(Dot11ProbeReq):
        print '[+] Detected 802.11 Probe Request Frame'
    elif pkt.haslayer(Dot11):
        print '[+] Detected .11 Frame'
    elif pkt.haslayer(Dot11Elt):
        print '[+] Detected IEEE 802.11 '
    # elif pkt.haslayer(TCP):
    #     print '[+] Detected a TCP Packet'
    # elif pkt.haslayer(DNS):
    #     print '[+] Detected a DNS Packet'

# 配置网卡名称信息
conf.iface = 'en0'
sniff(prn=pktPrint)
