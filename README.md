# About
pyscanlog3 (*py-scan-log-dee-three*) is a port scanning detection and logging tool written in Python3.
It is derived from the original pyscanlogd - https://github.com/pythonhacker/pyscanlogd which only
supports Python2.

The tool is able to detect vertical port scans. In other words, if any scanning tool performs
multiple port scans using TCP/UDP/SCTP techniques on the same host, the tool can detect it.

At present, it doesn't detect horizontal port scans (single port scanned across multiple hosts)
or single port scans (single port scanned in single host).

# Capabilities
pyscanlogd3 can detect most port scan techniques available using `nmap` and some by `hping3`. It uses `pypcap` library
for packet capturing and `dpkt` library for packet processing.

# Requirements.

1. A *nix (linux or similar) system with Python3 installed with support for sqlite3. The program is tested with Python3.11.
2. Root (sudo) access

The program needs root privilges to listen to the network interfaces in promiscious mode.

# Setup

1. Checkout the source code
2. Create a Python 3 virtualenv - Python 3.11 and higher are suggested.
3. Inside the virtual env,
    * pip install -r requirements.txt
    * python setup.py install

Once installation is complete, you can run the program using `pyscanlogd3` command.

# Running

Just running the program without any arguments,

	$ pyscanlogd3
	Scan logs will be saved to /var/log/pyscanlogd3.log
	listening to [None]
	duplicate scans will be logged
	config => threshold: 8, timeout: 5s, bufsize: 8192
	creating scan db /root/.config/pyscanlogd3/scan.db ...
	scan db created.
	listening on wlp0s20f3:

NOTE: The `pyscanlogd3` is a shell-script which runs with sudo access. It may ask you for your password if required. There is no need to run it with `sudo`.

The program by default runs in medium threshold mode. Scans are logged to a sqlite3 database and on the console.

For detailed command line options,

	$ pyscanlogd3 -h
	usage: pyscanlogd3 [-h] [-f LOGFILE] [-l {max,high,medium,low}] [-i [INTERFACE ...]] [-I]

	pyscanlogd3: Python3 port-scan detection program

	options:
	  -h, --help            show this help message and exit
	  -f LOGFILE, --logfile LOGFILE
							File to save logs to
	  -l {max,high,medium,low}, --level {max,high,medium,low}
							Default threshold level for detection
	  -i [INTERFACE ...], --interface [INTERFACE ...]
							The network interface(s) to listen to
	  -I, --ignore_duplicates
							Ignore continued (duplicate) scans

To listen to more than one interface, pass them to the `-i` option.

	$ pyscanlogd3 -i wlp0s20f3 lo
	Scan logs will be saved to /var/log/pyscanlogd3.log
	listening to ['wlp0s20f3', 'lo']
	duplicate scans will be logged
	config => threshold: 8, timeout: 5s, bufsize: 8192
	scan db /root/.config/pyscanlogd3/scan.db already exists.
	listening on wlp0s20f3: 
	listening on lo: 

For exiting press Ctrl-C. (once per interface).

	listening on wlp0s20f3: 
	listening on lo: 
	^CPress Ctrl-C again to exit
	stats for network interface: wlp0s20f3

	1 packets received by filter
	0 packets dropped by kernel
	^Cstats for network interface: lo

	2 packets received by filter
	0 packets dropped by kernel

# Scan detection and logging (nmap Examples)

While the program is running, try an `nmap` scan.

	$ sudo nmap -sX nmap.org

You should see the scan detected and logged on the console.

	[2024-08-25 19:36:14]: TCP Xmas scan (flags:41) from 192.168.1.6 to 50.116.1.184 (ports: [443, 80, 993, 1025, 1723])

As the scan continues, you will see more log lines like this as `nmap` scans more ports.

	[2024-08-25 19:36:14]: Continuing TCP Xmas scan (flags:41) from 192.168.1.6 to 50.116.1.184 (ports: [22, 23, 587, 139])
	[2024-08-25 19:36:16]: Continuing TCP Xmas scan (flags:41) from 192.168.1.6 to 50.116.1.184 (ports: [443, 8888, 110, 139, 587, 23, 22, 1723, 1025, 993, 1720, 5900, 3306, 3389, 143, 80, 113, 554, 199, 135, 8080, 21, 256])

The `Continuing` lines show a duplicate scan, i.e the same scan is detected as still running. To avoid detecting duplicate scans, you can pass the `-I` option.

Do another scan, this time an `ACK` scan.

	$ sudo nmap -sA nmap.org

	[2024-08-25 19:38:05]: TCP Ack scan (flags:16) from 192.168.1.6 to 50.116.1.184 (ports: [443, 1025, 8888, 113, 143, 111, 8080, 993, 23, 110, 21, 5900, 1723, 3389, 80, 25, 53, 135, 139, 445, 587, 256])

Let us do a UDP scan now.

	$ sudo nmap -sU nmap.org
	
	[2024-08-25 19:39:12]: UDP scan (flags:0) from 192.168.1.6 to 50.116.1.184 (ports: [36893, 40708, 5355, 20848, 8000, 43514, 215 68, 1434, 20164, 17824, 20154, 34555, 19017, 1900, 17487, 49158, 20560, 25337, 623, 20004, 997, 51972, 40539, 21333, 20, 45928,  1035, 49194, 177, 19161, 443, 50919, 30656, 43824, 16786, 34570, 33459, 518, 30718])

Scans are also logged to the scan db. By default this is created at `/root/.config/pyscanlogd3/scan.db` .

You can inspect the scans by opening the db.

	$ sudo sqlite3 /root/.config/pyscanlogd3/scan.db
	# Show all detected scans so far
	sqlite> select distinct type from scan;
	TCP Xmas
	TCP Ack
	TCP Null
	UDP
	# Show all distinct scans originating from 192.168.1.6 grouped by scan hash and type
	sqlite> select src,dst,type,hash,timestamp,utc_timestamp from scan where src='192.168.1.6' group by hash,type;
	192.168.1.6|50.116.1.184|TCP Ack|3654|1724594885.92384|2024-08-25 14:08:05
	192.168.1.6|50.116.1.184|TCP Null|3654|1724594941.4765|2024-08-25 14:09:01
	192.168.1.6|50.116.1.184|TCP Xmas|3654|1724594774.34435|2024-08-25 14:06:14
	192.168.1.6|50.116.1.184|UDP|3654|1724594952.29163|2024-08-25 14:09:12

NOTE: The tool right now ignores scans where src and dst IPs are the same. 

# Slow scan detection

The tool is able to detect slow scans as well. Use the `-T` option of nmap to try this out.

	$ sudo nmap -sS -T2  nmap.org
	[2024-08-25 19:43:27]: TCP Syn scan (flags:2) from 192.168.1.6 to 50.116.1.184 (ports: [256, 587, 3306, 23, 8080])

Paranod (`-T0`) and sneaky (`-T1`) scan types are very slow, so takes a while to detect.

# Known Issues

1. Detects spurious NULL TCP scans sometimes.
2. Detects spurious NULL UDP scans sometimes.
3. Slow scan detection is a work in progress.

# Bugs and Suggestions
For bugs file issues in the project. For feedback checkout my email in setup.py.

# LICENSE
The program is licensed under BSD 3-Clause license. Checkout `LICENSE` for details.



