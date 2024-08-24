# -- coding: utf-8
""" Module with utility functions """

import time
import socket
import struct

def timestamp():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

def ip2quad(x):
    return socket.inet_ntoa(struct.pack('I', x))

def scan_ip2quad(scan):
    return map(ip2quad, (scan.src, scan.dst))



