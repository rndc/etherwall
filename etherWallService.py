#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import time
from UnixDaemon import UnixDaemon
from NetMod import *
from GenWall import *
from ArpMon import *
from Error import Error
from ObtainGwHwAddr import ObtainGwHwAddr 

class etherWall(UnixDaemon):
	def __init__(self, pidfile, name):
		UnixDaemon.__init__(self,pidfile=pidfile,name=name)
	
	def run(self):
		self._startArpWall()
		self._flushArpCache()
		self._initNet()
		self._startEtherWall()

	def _startArpWall(self):
		"""
			Starting arptables rules
		"""
		self.logger.info("Changing arptables policy on chain INPUT & OUTPUT...")
		chain_start()

	def _flushArpCache(self):
		"""
			Flushing ARP cache
		"""
		self.logger.info("Deleting all ARP entries...")
		flush_arp_cache()
	
	def _initNet(self):
		"""
			Initialize the network interface configuration
		"""
      
		#
		# get_if_conf()  -- Fetching interface configuration by Automatically
		#
		# get_if_conf_ff() -- Fetching interface configuration from config file (/etc/etherwall/etherwall.conf)
		#    return 2 values:
		#      1. get_if_conf_ff()[0] is return message code number 
		#          0 - no error
		#          1 - bad parsing
		#          2 - device not found
		#	          3 - incomplete configuration format
		#      2. get_if_conf_ff()[1] is return message
		#   

		if (get_if_conf_ff()[0] == 0):
			# if the etherwall running with specified configuration
			if (get_if_conf_ff()[1]['manual'] == "yes"):
				self.iface = get_if_conf_ff()[1]['iface']
				self.logger.info("Listening on %s..." % (self.iface))
				self.mymac = get_if_conf_ff()[1]['hwaddr'].lower()
				self.myip = get_if_conf_ff()[1]['ipaddr']
				self.gw = get_if_conf_ff()[1]['gwaddr']
				self.gwmac = get_if_conf_ff()[1]['gwhwaddr'].lower()
				self.cidr = get_if_conf_ff()[1]['cidr']
				self.promisc = get_if_conf_ff()[1]['promisc']
				self.msgbox = get_if_conf_ff()[1]['msgbox']
				if not check_if_up(iface=self.iface):
					# ERROR: Interface is down
					Error("'Etherwall - Daemon Stopped'","'Interface: %s is down.'" % (self.iface),self.logger)
			else:
				# if the etherwall running with the automatic configuration detection
				if get_if_conf():
					self.iface = get_if_conf()[0]
					self.logger.info("Listening on %s..." % (self.iface))
					self.mymac = get_if_conf()[1]
					self.myip = get_if_conf()[2]
					self.gw = get_if_conf()[3]
					self.cidr = get_if_conf()[5]
					self.gwmac = self.getGwMac() 
					self.promisc = get_if_conf_ff()[1]['promisc']
					self.msgbox = get_if_conf_ff()[1]['msgbox']
				else:
					# ERROR: No Device Up or No IPv4 address assigned
					Error("'Etherwall - Daemon Stopped'","'Interface: No Device Up or No IPv4 address assigned.'",self.logger)
		elif (get_if_conf_ff()[0] == 1):
			# ERROR: Bad parsing
			Error("'Etherwall - Daemon Stopped'","'%s.'" % (get_if_conf_ff()[1]),self.logger)
		elif (get_if_conf_ff()[0] == 2):
			# ERROR: Device not found
			Error("'Etherwall - Daemon Stopped'","'%s.'" % (get_if_conf_ff()[1]),self.logger)
			alert.start()
			time.sleep(3)
		elif (get_if_conf_ff()[0] == 3):
			# ERROR: Incomplete configuration format
			Error("'Etherwall - Daemon Stopped'","'%s.'" % (get_if_conf_ff()[1]),self.logger)
	
	def getGwMac(self, gwhwaddr=None):
		"""
			Obtain the gateway MAC address 
		"""
		      
		# First attempt by DADM (Duplicate Address Detection Mode)
		self.logger.info("Trying to detect MAC address of the Gateway...")
		gwhwaddr = ObtainGwHwAddr(self.iface,self.mymac,"0.0.0.0",self.gw,self.logger)
		
		# If the first attempt failed
		if not gwhwaddr:
			self.logger.info("Re-trying to detect MAC address of Gateway...")
			gwhwaddr = ObtainGwHwAddr(self.iface,self.mymac,self.myip,self.gw,self.logger)
	
		if gwhwaddr:
			self.logger.info("MAC address detected for the Gateway: %s %s" % (self.gw,gwhwaddr))
			return gwhwaddr
		else:
			# ERROR: Couldn't obtain the gateway MAC address 
			Error("'Etherwall - Daemon Stopped'","'Couldn`t obtain the gateway MAC address'",self.logger)

	def _startEtherWall(self):
		""" Starting Etherwall """
      
		# adding router/gateway to ARP cache table as static ARP
		self.logger.info("Adding static entry for the Gateway: %s %s" % (self.gw, self.gwmac))
		if os.system("arp -s %s %s" % (self.gw, self.gwmac)):
			# ERROR: Couldn't add the static entry for the Gateway
			Error("'Etherwall - Daemon Stopped'","'Couldn't add the static entry for the Gateway.'",self.logger)
  
		# append gateway & another subnet/segment to chain
		app_gw_to_chain(gw=self.gw, mac=self.gwmac)
		app_another_subnet("%s/%s" % (self.myip,self.cidr))

		# adding the specified host to ARP cache tables as static ARP
		# and append host to chain.
		self.allow_host = {}
		if (imp_allow_host()[0] == 0):
			if imp_allow_host()[1]:
				for host in imp_allow_host()[1]:
					if (host.split()[1] == ("%s" % (self.mymac)) or host.split()[1] == ("%s" % (self.gwmac))):
						self.logger.critical("Forbidden: '%s': The MAC address same with your MAC & Gateway" % (host))
					else:
						self.logger.info("Adding static entry for the Host: %s" % (host))
						if os.system("arp -s %s" % (host)):
							self.logger.critical("Couldn't add the static entry, '%s' outside of subnet" % (host.split()[0]))
						else:
							# append host to chain 
							app_host_to_chain(ip=host.split()[0], mac=host.split()[1])
							self.allow_host['%s' % (host.split()[0])] = "%s" % (host.split()[1])
		else:
			# ERROR: Bad parsing
			Error("'Etherwall - Daemon Stopped'","'%s.'" % (imp_allow_host()[1]),self.logger)
		
		# sniffing mode
		if (self.promisc == "no"):
			self.logger.info("Device %s left promiscuous mode..." % (self.iface))
			scapy.all.conf.sniff_promisc = 0 
		else:
			self.logger.info("Device %s entered promiscuous mode..." % (self.iface))
		
		# starting realtime protection
		try:
			self.logger.info("Starting Realtime Protection...")
			arpmon = ArpMon(myip=self.myip, mymac=self.mymac, gw=self.gw, gwmac=self.gwmac, iface=self.iface, cidr=self.cidr, logger=self.logger, allow_host=self.allow_host, msgbox=self.msgbox)
			arpmon._startArpMon()
		except:
			if not check_if_up(iface=self.iface): # interface down
				# ERROR: interface error 
				Error("'Etherwall - Daemon Stopped'","'Interface: The interface %s went down.'" % (self.iface), self.logger)
			else:
				# ERROR: uknown/unexpected error 
				Error("'Etherwall - Daemon Stopped'","'Unexpected Error: %s'" % (sys.exc_info()[0]),self.logger)
	
## EOF ##
