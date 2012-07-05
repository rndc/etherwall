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
    def __init__(self, myip=None, mymac=None, target=None, iface=None, logger=None, allow_host={}):
      threading.Thread.__init__(self)
      self.myip = myip              # Own IP
      self.mymac = mymac            # Own MAC
      self.target = target          # Protected target
      self.iface = iface            # Own Interface
      self.logger = logger          # Logger
      self.allow_host = allow_host  # Allowed host = Protected hosts

    def run(self):
      """ Defense Solution """
      scapy.all.conf.verb = 0            # Verbosity off
      scapy.all.conf.iface = self.iface  # Set interface
      
      try:
	self.logger.info("Protection Thread to %s %s Started..." % (self.target,self.allow_host[self.target]))
	# Construct ARP 
	arp = scapy.all.ARP(hwdst=self.allow_host[self.target], hwsrc=self.mymac, pdst=self.target, psrc=self.myip, op=1)
	# Construct Ether frame
	frame = scapy.all.Ether(dst=self.allow_host[self.target])
	# Send packet
	scapy.all.sendp(frame/arp)
      except KeyError:
	pass
      
## EOF ##