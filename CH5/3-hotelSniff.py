#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from scapy.all import *


def findGuest(pkt):
    # raw = pkt.sprintf('%Raw.load%')

    # 测试
    raw = pkt

    name = re.findall('(?i)LAST_NAME=(.*)&', raw)
    room = re.findall("(?i)ROOM_NUMBER=(.*)'", raw)
    if name:
        # print '[+] Found Hotel Guest ' + str(name[0]) + ', Room #' + str(room[0])
        print "[+] Found Hotel Guest %s" % str(name)
    if room:
        print "[+] Found Room #%s" % str(room)

def test():
    test_arr = []
    test_arr.append("last_NAME=hehe&")
    test_arr.append("Room_number=''")

    for msg in test_arr:
        findGuest(msg)

def main():
    # 测试
    test()

    # 在这里不需要设置网卡参数
    # parser = optparse.OptionParser('usage %prog '+\
    #   '-i <interface>')
    # parser.add_option('-i', dest='interface',\
    #    type='string', help='specify interface to listen on')
    # (options, args) = parser.parse_args()
    #
    # if options.interface == None:
    #     print parser.usage
    #     exit(0)
    # else:
    #     conf.iface = options.interface

    # try:
    #     print '[*] Starting Hotel Guest Sniffer.'
    #     sniff(filter='tcp', prn=findGuest, store=0)
    # except KeyboardInterrupt:
    #     exit(0)


if __name__ == '__main__':
    main()
