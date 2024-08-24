# -- coding: utf-8
""" Module with utility functions """

import time
import socket
import struct
from dpkt import tcp

def unpack(ip):
    """ IP packet unpacked -> (src, dst, dport, proto, flags) """
    payload = ip.data
    proto = type(payload)
    src, dst, dport, flags = int(struct.unpack('I',ip.src)[0]),int(struct.unpack('I', ip.dst)[0]),int(payload.dport),0
    if proto == tcp.TCP:
        flags = payload.flags
    return src, dst, dport, proto, flags

def timestamp():
    """ Local timestamp formatted """
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

def ip2quad(x):
    """ IP integer to dotted quad a.b.c.d format """
    return socket.inet_ntoa(struct.pack('I', x))

def scan_ip2quad(scan):
    """ Scan ip addresses mapped to dotted quad a.b.c.d format """
    return map(ip2quad, (scan.src, scan.dst))



