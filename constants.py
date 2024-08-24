# -- coding: utf-8
""" TCP and UDP constants and protocols """

import dpkt

# TCP flag constants
TH_URG=dpkt.tcp.TH_URG
TH_ACK=dpkt.tcp.TH_ACK
TH_PSH=dpkt.tcp.TH_PUSH
TH_RST=dpkt.tcp.TH_RST
TH_SYN=dpkt.tcp.TH_SYN
TH_FIN=dpkt.tcp.TH_FIN

# Protocols
TCP=dpkt.tcp.TCP
UDP=dpkt.udp.UDP
SCTP=dpkt.sctp.SCTP

