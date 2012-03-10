#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import time
import logging
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

PtMDefense = False

class ProtectionThread(threading.Thread):
    def __init__(self, myip=None, mymac=None, gw=None, gwmac=None, iface=None, logger=None, allow_host=[]):
      threading.Thread.__init__(self)
      self.myip = myip
      self.mymac = mymac
      self.gw = gw
      self.gwmac = gwmac
      self.iface = iface
      self.logger = logger
      self.allow_host = allow_host
      
      if self.allow_host:
	PtMDefense = True
      else:
	PtMDefense = False

    def run(self):
      scapy.all.conf.verb = 0
      scapy.all.conf.iface = self.iface
      
      """ Point to Point Defense Solution """
      self.logger.info("Point to Point Protection Started...")
      # Construct ARP 
      arp = scapy.all.ARP(hwdst=self.gwmac, hwsrc=self.mymac, pdst=self.gw, psrc=self.myip, op=1)
      # Construct Ether frame
      frame = scapy.all.Ether(dst=self.gwmac)
      # Send packet
      scapy.all.sendp(frame/arp)
      
      """ Point to Multipoint Defense Solution """
      if PtMDefense:
	self.logger.info("Point to Multipoint Protection Started...")
	for host in self.allow_host:
	  ipdst = host.split()[0]
	  macdst = host.split()[1]
	  # Construct ARP 
	  arp = scapy.all.ARP(hwdst=macdst, hwsrc=self.mymac, pdst=ipdst, psrc=self.myip, op=2)
	  # Construct Ether frame
	  frame = scapy.all.Ether(src=self.mymac,dst=macdst)
	  # Send packet
	  scapy.all.sendp(frame/arp)

## EOF ##