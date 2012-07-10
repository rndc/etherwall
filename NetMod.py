#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import re
import sys
import random
import logging
import struct
import fcntl
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
import scapy.all
from socket import *

# Network interface path
SYS_NET_PATH  = "/sys/class/net"  # Is a directory
PROC_NET_PATH = "/proc/net/dev"   # Is a file

# Linux ARP cache path
LINUX_NET_ARP = "/proc/net/arp"  

# From linux/sockios.h
# socket configuration controls
SIOCGIFFLAGS   = 0x8913         # get flags
SIOCGIFNETMASK = 0x891b         # get network PA mask

# From linux/if.h
# standard interface flags 
IFF_UP = 0x1               # Interface is up.

# Loop back name
IFF_LOOP_BACK = "lo"

# Create socket
SOCK = socket(AF_INET, SOCK_DGRAM)

# Etherwall configuration path
ETHW_FILE = "/etc/etherwall/etherwall.conf"
ETHW_OUI_FILE = "/etc/etherwall/etherwall-oui.txt"
ALLOW_FILE = "/etc/etherwall/allow.conf"

# Regex to match the format of writing in etherwall.conf
ETHW_FILE_FORMAT = "[a-z]+=[\w:.-]"

# Regex to match the format of writing in allow.conf
ALLOW_FILE_FORMAT = "[0-9.]+-[a-zA-Z0-9:]"

# Regex to Match IPv4 + CIDR
IPv4_CIDR = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([1-9]|1[0-9]|2[0-9]|3[0-2])$"

# Regex to Match MAC Address
MAC_ADDR = "([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})"

####################
## OBTAIN SECTION ##
####################

def get_if_all():
	"""
		Get all the list of network interface
	"""
	
	if_all = []
	if os.path.exists(SYS_NET_PATH):
		for dev in os.listdir(SYS_NET_PATH):
			if_all.append(dev)
	else:
		for line in open(PROC_NET_PATH):
			dev = line.split()[0].split(':')[0]
			if_all.append(dev)
		if_all.pop(0)
		if_all.pop(0)
	
	return if_all

def get_if_conf():
	"""
		Get the network configuration automatically 
	"""
	
	for i in scapy.all.read_routes():
		if ((i[0] == 0) and (i[2] != '0.0.0.0')):
			ipgw = i[2]
			iface = i[3]
			ipaddr = i[4]
			hwaddr = scapy.all.get_if_hwaddr(iface)
			mask = inet_ntoa(fcntl.ioctl(SOCK, SIOCGIFNETMASK, struct.pack('256s', iface))[20:24])
			cidr = get_cidr(mask)
			break
	
	try:
		return (iface,hwaddr,ipaddr,ipgw,mask,cidr)
	except UnboundLocalError:
		return None

def get_if_conf_ff():
	"""
		Get the network configuration from file `/etc/etherwall/etherwall.conf' (specified configuration)
	"""
	#
	# This function return 2 values (message code number & message)
	# msg_code:
	#	0 - no error
	#	1 - bad parsing 
	#	2 - device not found
	#	3 - incomplete configuration format
	#
	# msg:
	#	return messages
	#
  
	# initial number code
	msg_code = 0
  
	# option and values
	config = {'manual':'no','iface':'','ipaddr':'','hwaddr':'','netmask':'','gwaddr':'','gwhwaddr':'','promisc':'no'}
  
	ethwfile = open(ETHW_FILE,'r')
  
	# match the configuration format in '/etc/etherwall/etherwall.conf'
	ethwfileformat = re.compile(ETHW_FILE_FORMAT)
  
	# match the hadrdware address input
	hwmatch = re.compile(MAC_ADDR)
  
	# Process of parsing can use the ConfigParser module, but I am prefer with the manual ways
	for n, line  in enumerate(ethwfile,1): # n is a line number
		if ethwfileformat.match(line.strip()):
			options = line.strip().split('=')[0]
			values = line.strip().split('=')[1]
			if options in config:
				if (options) == ('manual'):
					if (values == 'yes') or (values == 'no'):
						values = values
					else:
						msg_code = 1 # code number
						msg = ("Parsing: `%s`: must be `yes` or `no`, etherwall.conf: Line %s" % (line.strip(),n)) # message
						break
				if (options) == ('promisc'):
					if (values == 'yes') or (values == 'no'):
						values = values
					else:
						msg_code = 1
						msg = ("Parsing: `%s`: must be `yes` or `no`, etherwall.conf: Line %s" % (line.strip(),n))
						break
				if (options == 'iface'):
					if values in get_if_all():
						values = values
					else:
						msg_code = 2 
						msg = ("Interface: `%s`: Device not found, etherwall.conf: Line %s" % (line.strip(),n))
						break
				if (options == 'ipaddr') or (options == 'gwaddr') or (options == 'netmask'):
					if not check_ipv4(addr=values):
						msg_code = 1
						msg = ("Parsing: `%s`: Invalid IPv4 address, etherwall.conf: Line %s" % (line.strip(),n))
						break
				if (options == 'hwaddr') or (options == 'gwhwaddr'):
					if not hwmatch.match(values):
						msg_code = 1
						msg = ("Parsing: `%s`: Invalid MAC address, etherwall.conf: Line %s" % (line.strip(),n))
						break
				config[options] = values
			else:
				msg_code = 1 
				msg = ("Parsing: `%s`: Unknown Format, etherwall.conf: Line %s" % (line.strip(),n))
				break
		elif re.match('^#',line.strip()):
			pass
		elif (line.strip() == ""):
			pass
		else:
			msg_code = 1 
			msg = ("Parsing: `%s`: Bad Format, etherwall.conf: Line %s" % (line.strip(),n))
			break
	
	for keys in config:
		if (config[keys] == '' and msg_code == 0 and config['manual'] == 'yes'):
			msg_code = 3 
			msg = ("Configuration: `%s` is Needed, etherwall.conf: Line %s" % (keys,n))
			break
	
	if (msg_code == 0):
		# get cidr
		config['cidr'] = get_cidr(mask=config['netmask'])
		msg = config
		return msg_code, msg
	else:
		return msg_code, msg
	
	ethwfile.close()

def get_cidr(mask):
	"""
      Get CIDR by netmask
    """
	
	if (mask == '128.0.0.0'):
		return 1
	elif (mask == '192.0.0.0'):
		return 2
	elif (mask == '224.0.0.0'):
		return 3
	elif (mask == '240.0.0.0'):
		return 4
	elif (mask == '248.0.0.0'):
		return 5
	elif (mask == '252.0.0.0'):
		return 6
	elif (mask == '254.0.0.0'):
		return 7
	elif (mask == '255.0.0.0'):
		return 8
	elif (mask == '255.128.0.0'):
		return 9
	elif (mask == '255.192.0.0'):
		return 10
	elif (mask == '255.224.0.0'):
		return 11
	elif (mask == '255.240.0.0'):
		return 12
	elif (mask == '255.248.0.0'):
		return 13
	elif (mask == '255.252.0.0'):
		return 14
	elif (mask == '255.254.0.0'):
		return 15
	elif (mask == '255.255.0.0'):
		return 16
	elif (mask == '255.255.128.0'):
		return 17
	elif (mask == '255.255.192.0'):
		return 18
	elif (mask == '255.255.224.0'):
		return 19
	elif (mask == '255.255.240.0'):
		return 20
	elif (mask == '255.255.248.0'):
		return 21
	elif (mask == '255.255.252.0'):
		return 22
	elif (mask == '255.255.254.0'):
		return 23
	elif (mask == '255.255.255.0'):
		return 24
	elif (mask == '255.255.255.128'):
		return 25
	elif (mask == '255.255.255.192'):
		return 26
	elif (mask == '255.255.255.224'):
		return 27
	elif (mask == '255.255.255.240'):
		return 28
	elif (mask == '255.255.255.248'):
		return 29
	elif (mask == '255.255.255.252'):
		return 30
	elif (mask == '255.255.255.254'):
		return 31
	elif (mask == '255.255.255.255'):
		return 32

def get_dns():
    """
      DNS resolver configuration
    """
    try:
        dns = []
        dnsfile = open('/etc/resolv.conf', 'r')
        for line in dnsfile:
            dns.append(line.strip())

        dnsfile.close()
        return dns
    except:
        return False

def get_fake_hwaddr():
    """
      Generate the fake hardware address
    """
    hwaddr = [ 0x00,
	     random.randint(0x00, 0xff),
	     random.randint(0x00, 0xff),
	     random.randint(0x00, 0xff),
	     random.randint(0x00, 0xff),
	     random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, hwaddr))

def imp_allow_host():
	"""
		Import the list of allowed hosts
	"""
	
	#
	# This function return 2 values (message code number & message)
	# msg_code:
	#	0 - no error
	#	1 - bad parsing 
	#
	# msg:
	#	return messages
	#
  
	# initial code number
	msg_code = 0
  
	# put a list of hosts that are allowed
	allow_host = []
  
	allowfile = open(ALLOW_FILE,'r')
  
	# match the configuration format in '/etc/etherwall/allow.conf'
	allowfileformat = re.compile(ALLOW_FILE_FORMAT)
  
	# match the hadrdware address input
	hwmatch = re.compile(MAC_ADDR)
  
	# parsing by manual
	for n, host in enumerate(allowfile,1): # n is a line number
		if allowfileformat.match(host.strip()):
			ipaddr = host.strip().split('-')[0]
			hwaddr = host.strip().split('-')[1]
			if not (check_ipv4(addr=ipaddr)):
				msg_code = 1 
				msg = ("Parsing: `%s`: Invalid IPv4 address, allow.conf: Line %s" % (host.strip(),n))
				break
			if not hwmatch.match(hwaddr):
				msg_code = 1 
				msg = ("Parsing: `%s`: Invalid MAC address, allow.conf: Line %s" % (host.strip(),n))
				break
			allow_host.append("%s %s" % (ipaddr,hwaddr.lower()))
		elif re.match('^#',host.strip()):
			pass
		elif (host.strip() == ""):
			pass
		else:
			msg_code = 1 
			msg = ("Parsing: `%s`: Bad Format, allow.conf: Line %s" % (host.strip(),n))
			break
	
	if (msg_code == 0):
		msg = allow_host
		return msg_code, msg
	else:
		return msg_code, msg
    
	allowfile.close() 

###################
## CHECK SECTION ##
###################

def check_if_up(iface=None):
	"""
		Check whether the interface is up
	"""
	# by scapy
	# if iface in scapy.all.get_working_if():
	#  return True	# is Up
	# else:
	#  return False	# is Down
	
	ifreq = struct.pack('16sh', iface, 0)
	flags = struct.unpack('16sh', fcntl.ioctl(SOCK.fileno(), SIOCGIFFLAGS, ifreq))[1]
	
	if (iface == IFF_LOOP_BACK):
		return False 	# is Down
	elif (flags & IFF_UP):
		return True		# is Up
	else:
		return False	# is Down

def check_ipv4(addr=None):
	"""
		Check the IPv4 address format 
	"""
	
	try:
		if (len(addr.split(".")) == 4):
			inet_aton(addr)
			return True 	# IPv4 Valid
		else:
			return False	# IPv4 Invalid
	except error:
		ipv4cidr = re.compile(IPv4_CIDR)
		if (ipv4cidr.match(addr)):
			return True		# IPv4+CIDR/Prefix Valid
		else:
			return False	# Invalid IPv4 address or Invalid CIDR

def check_mac_vendor(mac=None, info=False, macvendor=False):
	"""
		Check the MAC Address Vendor
	"""
	
	# convert mac to  upper case
	mac = mac.upper()
	
	# match the hadrdware address 
	hwmatch = re.compile(MAC_ADDR)
	
	# open oui file (database vendor file)
	ouifile = open(ETHW_OUI_FILE).read()
	ouifile = ouifile.split("\n\n")
	
	if hwmatch.match(mac):
		# 3 byte for identification vendor
		mac = mac[0:2]+'-'+mac[3:5]+'-'+mac[6:8]
		
		for line in ouifile:
			if mac in line:
				if info:
					mac = line
				else:
					mac = line.split()
				macvendor = True
				break
	
		if macvendor: # mac vendor found !
			if not info: # information is not complete, just vendor
				for n, i in enumerate(mac, 1):
					if (i == ("(hex)")):
						hexline = n
					if (i == mac[0].replace("-","")):
						macline = n
				return " ".join(mac[hexline:macline-1])
			else: # information complete, about country, address, etc
				return mac
		else: # mac vendor not found !
			mac = "Unknown"
			return mac
	else:
		return False  # invalid MAC address

def flush_arp_cache():
	"""
		Delete all ARP entry
	"""
	for ip in open(LINUX_NET_ARP,'r'):
		if check_ipv4(ip):
			os.system("arp -d %s &> /dev/null" % (ip.split()[0]))
    
## EOF ##
