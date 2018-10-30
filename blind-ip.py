#!/usr/bin/env python

"""blind-ip.py: Blind sensitive IP addresses"""

#Usage is ./pcap-rewrite.py <input pcap file> <blinding template> <outputfile>

__author__ = "Brent Shaw"
__copyright__ = "Copyright 2018"
__credits__ = ["Brent Shaw"]
__license__ = "GPL"
__version__ = "0.1.0"
__maintainer__ = "Brent Shaw"
__email__ = "shaw@live.co.za"
__status__ = "Development"

from colourterm import tform
import ipaddress
import logging, sys
from scapy.all import *
import socket
import struct

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def inSubnet(ip, subnet):
	if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
		return True
	else:
		return False

def maskIP(ip, mask):
	ip_integer = ip2int(ip)
	mask_integer = ip2int(mask)
	return int2ip(ip_integer & mask_integer)

if len(sys.argv) != 4:
	print('Usage is: '+tform('$python blind-ip.py <original pcap file> <rule file> <output pcap file>', "WARNING"))
	print('Example usage: '+tform('$python blind-ip.py original.pcap rules.ip /tmp/blind.pcap', "WARNING"))
	sys.exit(1)

pcap = sys.argv[1]
rulefile = sys.argv[2]
outfile = sys.argv[3]

rules = []

with open(rulefile, 'r') as f:
	for line in f:
		rules.append(line.split())

pkts = rdpcap(pcap)

for p in pkts:
	del p[IP].chksum
	if p.haslayer(TCP):
		del p[TCP].chksum
	for rule in rules:
		if p.haslayer(IP) and inSubnet(p[IP].src, rule[0]):
			p[IP].src = maskIP(p[IP].src, rule[1])
		if p.haslayer(IP) and inSubnet(p[IP].dst, rule[0]):
			p[IP].dst = maskIP(p[IP].dst, rule[1])

wrpcap(outfile, pkts)

print(" - Capture successfully blinded")