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
# Custom TCP flag OR constants
TH_SYN_RST=TH_SYN|TH_RST
TH_URG_PSH_FIN=TH_URG|TH_PSH|TH_FIN
TH_URG_PSH_FIN_ACK=TH_URG|TH_PSH|TH_FIN|TH_ACK
TH_SYN_FIN=TH_SYN|TH_FIN
TH_FIN_ACK=TH_FIN|TH_ACK
TH_SYN_ACK=TH_SYN|TH_ACK
TH_SYN_ACK_RST=TH_SYN|TH_ACK|TH_RST
TH_RST_ACK=TH_RST|TH_ACK
TH_ALL_FLAGS=TH_URG|TH_PSH|TH_ACK|TH_RST|TH_SYN|TH_FIN

# Protocols
TCP=dpkt.tcp.TCP
UDP=dpkt.udp.UDP
SCTP=dpkt.sctp.SCTP

# Scan names
# Ref: https://nmap.org/book/man-port-scanning-techniques.html
TCP_NULL_SCAN='TCP Null'
TCP_FIN_SCAN='TCP Fin'
TCP_SYN_SCAN='TCP Syn'
TCP_SYN_FIN_SCAN='TCP Syn/Fin'
TCP_XMAS_SCAN='TCP Xmas'
TCP_ACK_SCAN='TCP Ack'
TCP_FIN_ACK_SCAN='TCP Fin/Ack (Maimon)'
TCP_FULL_CONNECT_SCAN='TCP Full-Connect'
TCP_ALL_FLAGS_SCAN='TCP All-Flags'
TCP_IDLE_SCAN='TCP Idle'
UDP_SCAN='UDP'

# Not a scan
TCP_REPLY='Reply'

