#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import time
import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from NetMod import *
from ProtectionThread import *
from Alert import Alert
from Error import Error

class ArpMon():
	""" ARP monitoring """ 
	def __init__(self, myip=None, mymac=None, gw=None, gwmac=None, iface=None, cidr=None, logger=None, allow_host={}, msgbox=None):
		self.myip = myip							# Own IP
		self.mymac = mymac							# Own MAC
		self.gw = gw								# Gateway IP
		self.gwmac = gwmac							# Gateway MAC
		self.iface = iface							# Own interface
		self.cidr = cidr							# Classless inter-domain routing
		self.logger = logger						# Logger
		self.msgbox = msgbox						# Message box
		self.allow_host = allow_host				# Allowed host = Protected hosts
		self.host_list = {}							# Hosts list
		self.spoofer_list = []						# Spoofer list 
		self.allow_host[self.myip] = self.mymac		# Add new entry (own ip&mac) to allow_host
		self.allow_host[self.gw] = self.gwmac		# Add new entry (gateway ip&mac) to allow_host
		
		for ip,hw in self.allow_host.items():
			self.host_list[ip] = hw

	def _startArpMon(self):
		""" 
			Start ARP monitor 
		"""
		self.logger.info("Realtime Protection Actived !")
		sniff(prn=self.capture, filter="arp", store=0, iface=self.iface) # sniff time !

	def capture(self, pkt):
		"""
			Capturing ARP packet
		"""
		if (ARP in pkt):
			# source packet
			psrc = pkt.sprintf("%ARP.psrc%")
			hwsrc = pkt.sprintf("%ARP.hwsrc%")
			# destination packet
			pdst = pkt.sprintf("%ARP.pdst%")
			hwdst = pkt.sprintf("%ARP.hwdst%")
			ethdst = pkt.sprintf("%Ether.dst%")
			# operation code
			op = pkt.sprintf("%ARP.op%")
			# opcode 1
			if (op == "who-has"):
				return self.op_request(psrc, hwsrc, pdst, hwdst, ethdst)
			# opcode 2
			elif (op == "is-at"):
				return self.op_reply(psrc, hwsrc, pdst, hwdst)

	def op_request(self, psrc, hwsrc, pdst, hwdst, ethdst):
		"""
			Operation Code 1 = Request
		"""
		phsrc = "%s %s" % (psrc, hwsrc)
		
		try:
			if (hwsrc == self.host_list[psrc]):
				pass
			elif (self.allow_host.__contains__(psrc)):
				# ARP spoofing/poisoning
				for ip,hw in self.host_list.items():
					if (hwsrc == hw):
						self.logger.warning("Spoofing Detected: %s %s pretends to be %s" %(ip,hw,psrc))
						self._earlyWarning(("%s %s" % (ip,hw)),psrc)
						self._startProtection(psrc)
						ip = False
						break
				# Duplicate IP
				if ip:
					self.logger.warning("IP Conflict: [%s] wants to be %s" % (hwsrc,psrc))
					self._startProtection(psrc)
		except KeyError:
			# auto add by Broadcast ARP Detected
			if (ethdst == "ff:ff:ff:ff:ff:ff" or hwdst == "00:00:00:00:00:00" or hwdst == "ff:ff:ff:ff:ff:ff"):
				if (psrc != "0.0.0.0"):
					for ip,hw in self.host_list.items():
						# IP change, if the hardware source isn't gateway hardware address
						if (hwsrc != self.gwmac):
							if (hwsrc == hw):
								del self.host_list[ip]
								self.host_list[psrc] = hw
								self.logger.info("IP Change: %s %s -> %s" % (ip,hw,phsrc))
								break
					if hwsrc != hw:
						self.logger.info("New Host: %s" % phsrc)
						self.host_list[psrc] = hwsrc

	def op_reply(self, psrc, hwsrc, pdst, hwdst):
		"""
			Operation Code 2 = Reply
		"""
		
		phsrc = "%s %s" % (psrc, hwsrc)
		
		try:
			if (self.host_list[psrc] == hwsrc):
				pass
			elif (self.allow_host.__contains__(psrc)):
				# ARP spoofing/poisoning
				for ip,hw in self.host_list.items():
					if (hwsrc == hw):
						self.logger.warning("Spoofing Detected: %s %s pretends to be %s" %(ip,hw,psrc))
						self._earlyWarning(("%s %s" % (ip,hw)),psrc)
						self._startProtection(psrc)
						ip = False
						break
				
				# Duplicate IP
				if ip:
					self.logger.warning("IP Conflict: [%s] wants to be %s" % (hwsrc,psrc))
					self._startProtection(psrc)
		except KeyError:
			pass
	
	def _startProtection(self,target):
		try:
			pt = ProtectionThread(myip=self.myip, mymac=self.mymac, target=target, iface=self.iface, logger=self.logger, allow_host=self.allow_host)
			pt.start()
		except:
			# ERROR: thread over !
			Error("'Etherwall - Daemon Stopped'","'Realtime Protection Stoped: Thread Over !'",self.logger)
	
	def _earlyWarning(self, spoofer, target):
		if (spoofer in self.spoofer_list):
			pass
		else:
			self.spoofer_list.append(spoofer)
			# WINDOW: spoofing detected !
			alert = Alert("'Etherwall - ARP Spoofing Detected !'","'ARP from %s [%s] \npretends to be %s.'" % (spoofer.split()[0],spoofer.split()[1],target),self.msgbox)
			alert.start()

## EOF ##
