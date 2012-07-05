#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import random
import threading
from scapy.all import *
from NetMod import get_fake_hwaddr

gw_list = []

class pSend(threading.Thread):
    def __init__(self, iface,ip,gw):
      threading.Thread.__init__(self)
      
      # init value
      self.gw = gw
      self.ip = ip
      self.static_fake = "%s" % (get_fake_hwaddr())

      # init config
      conf.verb = 0
      conf.iface = iface
      
    def run(self):
	for i in range(0,3):
          if (random.randint(0,1) == 1):
	    sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,hwsrc=get_fake_hwaddr(),pdst=self.gw,hwdst="00:00:00:00:00:00"),count=3)
	    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,pdst=self.gw,hwdst="00:00:00:00:00:00"),count=i) 
	    sendp(Ether(src=self.static_fake,dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,hwsrc=self.static_fake,pdst=self.gw,hwdst="00:00:00:00:00:00"),count=i)
	  else:
	    sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,hwsrc=get_fake_hwaddr(),pdst=self.gw,hwdst="00:00:00:00:00:00"),count=3)
	    sendp(Ether(src=self.static_fake,dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,hwsrc=self.static_fake,pdst=self.gw,hwdst="00:00:00:00:00:00"),count=i)
	    sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.ip,pdst=self.gw,hwdst="00:00:00:00:00:00"),count=i)
	    
def ArpReply(pkt):
    if (ARP in pkt):
      op = pkt.sprintf("%ARP.op%") 
      psrc = pkt.sprintf("%ARP.psrc%")      
      hwsrc = pkt.sprintf("%Ether.src%")
      pdst = pkt.sprintf("%ARP.pdst%")
      hwdst = pkt.sprintf("%Ether.dst%")
      
      if (op == "is-at" and psrc == mygw):
	if (pdst == myip and hwdst == mymac):
	  phsrc = "%s-%s" % (psrc,hwsrc)
	  if phsrc not in gw_list:
	    gw_list.append(phsrc)
      
def ObtainGwHwAddr(iface,mac,ip,gw):
    global mygw,myip,mymac
    mymac = mac
    myip = ip
    mygw = gw
    
    ps = pSend(iface,myip,mygw)
    ps.start()
    sniff(iface=iface, prn=ArpReply, filter="arp", store=0, timeout=10)
    if len(gw_list) == 1:
      	return gw_list[0].split("-")[1]
    else:
      	return None

## EOF ##