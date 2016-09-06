# -*- coding: utf-8 -*-
import socket

result = socket.gethostbyname("www.baidu.com")

print "[+] host name: %s ---> ip address: %s" % ("wwww.baidu.com", str(result))

ip_addr = str(result)
rs2 = socket.gethostbyaddr(ip_addr)

print "[+] ip address: %s ---> host name: %s" % (ip_addr, str(rs2))
