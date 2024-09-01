# -- coding: utf-8
""" Module with utility functions """

import sys, os
import time
import socket
import struct
from dpkt import tcp
from datetime import datetime

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

def timestamp_to_utc(ts):
    """ Return unix timestamp to UTC """
    return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        
def ip2quad(x):
    """ IP integer to dotted quad a.b.c.d format """
    return socket.inet_ntoa(struct.pack('I', x))

def quad2ip(x):
    """ IP dotted quad a.b.c.d -> integer mapping """
    return struct.unpack('I',socket.inet_aton(x))[0]
    
def scan_ip2quad(scan):
    """ Scan ip addresses mapped to dotted quad a.b.c.d format """
    return map(ip2quad, (scan.src, scan.dst))

def is_running(pidfile='/var/run/pyscanlogd3.pid'):
    """ Check if the process with given pidfile is running """

    try:
        pid=open(pidfile).read()
        os.kill(int(pid), 0)
        return pid, True
    except ProcessLookupError as e:
        print(e)
        return pid,False
    except Exception as e:
        print(e)
        return pid, False
    
def daemonize(pidfile='/var/run/pyscanlogd3.pid'):
    # Disconnect from tty
    try:
        pid = os.fork()
        if pid>0:
            sys.exit(0)
    except OSError as e:
        print(f"fork #1 failed {e}", file=sys.stderr)
        sys.exit(1)

    os.setsid()
    os.umask(0)

    # Second fork
    try:
        pid = os.fork()
        if pid>0:
            open(pidfile,'w').write(str(pid))
            sys.exit(0)
    except OSError as e:
        print(f"fork #1 failed {e}", file=sys.stderr)        
        sys.exit(1)    
