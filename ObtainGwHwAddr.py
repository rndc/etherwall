#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import random
import threading
from scapy.all import *
from NetMod import get_fake_hwaddr

hw_list1 = [] # list of a hardware reply 
hw_list2 = [] # if you get a hardware reply that has previously been registered in hw_list1, adding to this list

class pSend(threading.Thread):
	def __init__(self, iface,psrc,pdst):
		threading.Thread.__init__(self)
		
		# init value
		self.pdst = pdst
		self.psrc = psrc
		
		# init config
		conf.verb = 0
		conf.iface = iface
	
	def run(self):
		# delay for 1/sec, until sniffer ready !
		time.sleep(1)
		
		# randomized to prevent your mac address is detected by a malicious host
		if (random.randint(0,1) == 1):
			sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,hwsrc=get_fake_hwaddr(),pdst=self.pdst,hwdst="00:00:00:00:00:00"))
			sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,pdst=self.pdst,hwdst="00:00:00:00:00:00")) 
			sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,hwsrc=get_fake_hwaddr(),pdst=self.pdst,hwdst="00:00:00:00:00:00"))
		else:
			sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,hwsrc=get_fake_hwaddr(),pdst=self.pdst,hwdst="00:00:00:00:00:00"))
			sendp(Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,hwsrc=get_fake_hwaddr(),pdst=self.pdst,hwdst="00:00:00:00:00:00"))
			sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc=self.psrc,pdst=self.pdst,hwdst="00:00:00:00:00:00"))
  
def ArpReply(pkt):
	if (ARP in pkt):
		op = pkt.sprintf("%ARP.op%") 
		psrc = pkt.sprintf("%ARP.psrc%")
		hwsrc = pkt.sprintf("%Ether.src%")
		pdst = pkt.sprintf("%ARP.pdst%")
		hwdst = pkt.sprintf("%Ether.dst%")
			
		if (op == "is-at" and psrc == mygw):
			if (pdst == myip and hwdst == mymac):
				if (hwsrc not in hw_list1):
					hw_list1.append(hwsrc)
				elif (hwsrc not in hw_list2):
					hw_list2.append(hwsrc)	

def ObtainGwHwAddr(iface,mac,ip,gw,logger):
	global mygw,myip,mymac
	mymac = mac
	myip = ip
	mygw = gw
	logger = logger
	
	# ARP request to Gateway
	ps = pSend(iface,myip,mygw)
	ps.start()
	
	# Capture ARP reply from Gateway, timeout is 10 seconds
	sniff(iface=iface, prn=ArpReply, filter="arp", store=0, timeout=10)
	
	# Sanity results
	if (len(hw_list1) == 1 and len(hw_list2) == 0):
		return hw_list1[0] 
	elif (len(hw_list1) >= 1 and len(hw_list2) >=1):
		for mac in hw_list2:
			if (mac in hw_list1):
				logger.warning("Possibility is a fake ARP reply:  [%s] pretends to be %s" % (mac,mygw))
				hw_list1.remove(mac)
		if (len(hw_list1) == 1):
			return hw_list1[0] 
		else:	
			logger.warning("Couldn't obtain the trusted hardware address")
			return None  	 
	elif (len(hw_list1) > 1 and len(hw_list2) == 0):
		logger.warning("More than one ARP reply received, It might be caused attacks by malicious host")
		return None
	else:
		return None # No answer

## EOF ##
