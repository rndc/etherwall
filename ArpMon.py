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

class ArpMon():
    """ ARP monitoring """ 
    def __init__(self, myip=None, mymac=None, gw=None, gwmac=None, iface=None, cidr=None, logger=None, allow_host=[]):
      self.myip = myip
      self.mymac = mymac
      self.gw = gw
      self.gwmac = gwmac
      self.iface = iface
      self.cidr = cidr
      self.logger = logger
      self.dup = 1
      self.ipchanged = 0
      self.ip = []
      self.allow_host = allow_host
      self.host_list = []
      self.spoofer_list = []
      self.host_list.append("%s %s" % (self.myip,self.mymac))
      self.host_list.append("%s %s" % (self.gw,self.gwmac))
      
      
      if self.allow_host:
	for host in self.allow_host:
	  self.host_list.append(host)
	

    def _startArpMon(self):
      """ 
	Start ARP monitor 
      """
      self.bcast_to_host_list()
      self.logger.info("Realtime Protection Actived !")
      sniff(prn=self.capture, filter="arp", store=0, iface=self.iface)

    def bcast_to_host_list(self):
      """
	Broadcast Network by Arping
      """
      scapy.all.conf.verb = 0
      scapy.all.conf.iface = self.iface

      # fake address
      for i in range(0,2):
	ans,unans = srp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="0.0.0.0",hwsrc=get_fake_hwaddr(),pdst=self.gw,hwdst="ff:ff:ff:ff:ff:ff"), timeout=1)

      # duplicate address detection mode
      ans,unans = srp(Ether(src=self.mymac,dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="0.0.0.0",hwsrc=self.mymac,pdst="%s/%s" % (self.myip,self.cidr),hwdst="ff:ff:ff:ff:ff:ff"), timeout=5)

      for snd,rcv in ans:
	host = rcv.sprintf(r"%ARP.psrc% %Ether.hwsrc%")
	if (host in self.host_list):
	  pass
	else:
	  if (host.split()[0] == self.myip or host.split()[0] == self.gw):
	    pass
	  else:
	    self.logger.info("Added Host: %s" % host)
	    self.host_list.append(host)

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
      
      if  (phsrc in self.host_list):
	pass
      else:
	if (psrc == self.myip or psrc == self.gw):
	  # ARP spoofing/poisoning
	  for i in self.host_list:
	    if (hwsrc == i.split()[1]):
	      self.logger.warning("Spoofing Detected: %s pretends to be %s" %(i,psrc))
	      self._earlyWarning(i,psrc)
	      self._startProtection()
	      self.dup = 0
	      break
	  # duplicate ip 
	  if self.dup:
	    self.logger.warning("IP Conflict: [%s] wants to be %s" %(hwsrc,psrc))
	    if (psrc == self.myip):
	      self._startProtection()
	  self.dup = 1
	else:
	  # auto add by Broadcast ARP Detected
	  if (ethdst == "ff:ff:ff:ff:ff:ff" or hwdst == "00:00:00:00:00:00" or hwdst == "ff:ff:ff:ff:ff:ff"):
	    if (psrc != "0.0.0.0"):
	      for i in self.host_list:
		# IP change, if the hardware source isn't gateway hardware address
		if (hwsrc != self.gwmac):
		  if (hwsrc == i.split()[1]):
		    self.logger.info("IP Change: %s -> %s" % (i,phsrc))
		    self.host_list.remove(i)
		    self.host_list.append(phsrc)
		    self.ipchanged = 1
		    break
	      if not self.ipchanged:
		self.logger.info("New Host: %s" % phsrc)
		self.host_list.append(phsrc)
	      self.ipchanged = 0	
						
    def op_reply(self, psrc, hwsrc, pdst, hwdst):
      """
	Operation Code 2 = Reply
      """
      
      phsrc = "%s %s" % (psrc, hwsrc)
      
      if  (phsrc in self.host_list):
	pass
      else:
	if (psrc == self.myip or psrc == self.gw):
	  # ARP spoofing/poisoning
	  for i in self.host_list:
	    if (hwsrc == i.split()[1]):
	      self.logger.warning("Spoofing Detected: %s pretends to be %s" %(i,psrc))
	      self._earlyWarning(i,psrc)
	      self._startProtection()
	      break
	
	if (psrc== self.myip and hwsrc != self.mymac):
	  self.logger.warning("IP Conflict: [%s] wants to be %s" %(hwsrc,psrc))
	  self._startProtection()
	
	if (pdst == self.myip and hwdst != self.mymac):
	  self.logger.warning("IP Conflict: [%s] wants to be %s" %(hwdst,pdst))
	  self._startProtection()

  
    def _startProtection(self):
      try:
	pt = ProtectionThread(myip=self.myip, mymac=self.mymac, gw=self.gw, gwmac=self.gwmac, iface=self.iface, logger=self.logger, allow_host=self.allow_host)
	pt.start()
      except:
	# WINDOW: thread over !
	alert = Alert(0,"'Etherwall - Daemon Stopped'","'Realtime Protection Stoped: Thread Over !'",self.logger)
	alert.start()
	time.sleep(3)

    def _earlyWarning(self, spoofer, target):	
      if (spoofer in self.spoofer_list):
	pass
      else:
	self.spoofer_list.append(spoofer)
	# WINDOW: spoofing detected !
	alert = Alert(1,"'Etherwall - ARP Spoofing Detected !'","'ARP from %s [%s] \npretends to be %s.'" % (spoofer.split()[0],spoofer.split()[1],target),self.logger)
	alert.start()

## EOF ##