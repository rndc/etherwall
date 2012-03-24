#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import threading
from scapy.all import *
from NetMod import get_fake_hwaddr

gw_list = []

class pSend(threading.Thread):
    def __init__(self, iface,gw):
      threading.Thread.__init__(self)
      self.gw = gw
      
      conf.verb = 0
      conf.iface = iface
      
    def fakePacket(self):
	"""
	  Fake Packet
	"""
	for i in range(0,3):
	  sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="0.0.0.0",hwsrc=get_fake_hwaddr(),pdst=self.gw,hwdst="00:00:00:00:00:00"),count=2)
    
    def truePacket(self):
	"""
	  True Packet
	"""
	sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="0.0.0.0",pdst=self.gw,hwdst="00:00:00:00:00:00"),count=255)
	
    def run(self):
      self.fakePacket()
      self.truePacket()

      
def ArpReply(pkt):
    if (ARP in pkt):
      op = pkt.sprintf("%ARP.op%") 
      psrc = pkt.sprintf("%ARP.psrc%")      
      hwsrc = pkt.sprintf("%Ether.src%")
      pdst = pkt.sprintf("%ARP.pdst%")
      hwdst = pkt.sprintf("%Ether.dst%")
      
      if (op == "is-at" and psrc == mygw):
	if (pdst == "0.0.0.0" and hwdst == mymac):
	  phsrc = "%s-%s" % (psrc,hwsrc)
	  if phsrc not in gw_list:
	    gw_list.append(phsrc)
      
def ObtainGwHwAddr(iface,gw,ip,mac):
    global mygw,myip,mymac
    mygw = gw
    myip = ip
    mymac = mac
    ps = pSend(iface,mygw)
    ps.start()
    sniff(iface=iface, prn=ArpReply, filter="arp", store=0, timeout=10)
    if len(gw_list) == 1:
      return gw_list[0].split("-")[1]
    else:
      return None
    
## EOF ##