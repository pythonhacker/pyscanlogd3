# About
pyscanlog3 (*py-scan-log-dee-three*) is a port scanning detection and logging tool written in Python3.
It is derived from the original pyscanlogd - {https://github.com/pythonhacker/pyscanlogd} which only
supports Python2.

The tool is able to detect vertical port scans. In other words, if any scanning tool performs
multiple port scanning using TCP/UDP/SCTP scans, the tool can detect it. At present, it doesn't
detect horizontal port scans (single port scanned across multiple hosts) or single port scans
(single port scanned in single host).

# Capabilities
pyscanlogd3 can detect most port scan techniques available using `nmap` and some by `hping3`. 

# Setup
Coming soon.
