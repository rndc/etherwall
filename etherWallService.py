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
from Alert import Alert

class etherWall(UnixDaemon):
    def __init__(self, pidfile, name):
      UnixDaemon.__init__(self,pidfile=pidfile,name=name)

    def run(self):
      self._initNet()
      self._startEtherWall()
        
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
      #          3 - incomplete configuration format
      #      2. get_if_conf_ff()[1] is return message
      #   

      if (get_if_conf_ff()[0] == 0):
	# from config file
	if get_if_conf_ff()[1]['manual'] == "yes":
	  self.iface = get_if_conf_ff()[1]['iface']
	  self.logger.info("Listening on %s..." % (self.iface))
	  self.mymac = get_if_conf_ff()[1]['hwaddr'].lower()
	  self.myip = get_if_conf_ff()[1]['ipaddr']
	  self.gw = get_if_conf_ff()[1]['gwaddr']
	  self.gwmac = get_if_conf_ff()[1]['gwhwaddr'].lower()
	  self.cidr = get_if_conf_ff()[1]['cidr']
	  self.promisc = get_if_conf_ff()[1]['promisc']
	  if not check_if_up(iface=self.iface):
	    # fatal error will be stop the daemon
	    self.logger.error("Interface: %s is down" % (self.iface))
	    self.logger.error("Daemon Stopped.")
	    sys.exit(1)
	else:
	  # by automatically
	  if get_if_conf():
	    self.iface = get_if_conf()[0]
	    self.logger.info("Listening on %s..." % (self.iface))
	    self.mymac = get_if_conf()[1]
	    self.myip = get_if_conf()[2]
	    self.gw = get_if_conf()[3]
	    self.cidr = get_if_conf()[5]
	    self.gwmac = self.getGwMac() 
	    self.promisc = get_if_conf_ff()[1]['promisc']
	  else:
	    # fatal error will be stop the daemon
	    self.logger.error("Interface: No Device Up")
	    self.logger.error("Daemon Stopped.")
	    sys.exit(1)
      elif (get_if_conf_ff()[0] == 1):
	# fatal error will be stop the daemon
	self.logger.error("%s" % (get_if_conf_ff()[1]))
	self.logger.error("Daemon Stopped.")
	sys.exit(1)
      elif (get_if_conf_ff()[0] == 2):
	# fatal error will be stop the daemon
	self.logger.error("%s" % (get_if_conf_ff()[1]))
	self.logger.error("Daemon Stopped.")
	sys.exit(1)
      elif (get_if_conf_ff()[0] == 3):
	# fatal error will be stop the daemon
	self.logger.error("%s" % (get_if_conf_ff()[1]))
	self.logger.error("Daemon Stopped.")
	sys.exit(1)


    def getGwMac(self, verb=0, hwaddr=None):
      """
	Obtain the gateway MAC address by arping
      """
      self.verb = verb
      scapy.all.conf.verb = self.verb
      scapy.all.conf.iface = self.iface
      
      # fake address
      for i in range(0,2):
	scapy.all.srp(scapy.all.Ether(src=get_fake_hwaddr(),dst="ff:ff:ff:ff:ff:ff")/scapy.all.ARP(psrc="0.0.0.0",hwsrc=get_fake_hwaddr(),pdst=self.gw,hwdst="ff:ff:ff:ff:ff:ff"), timeout=1)

      # duplicate address detection mode
      ans,unans = scapy.all.srp(scapy.all.Ether(src=self.mymac,dst="ff:ff:ff:ff:ff:ff")/scapy.all.ARP(psrc="0.0.0.0",hwsrc=self.mymac,pdst=self.gw,hwdst="ff:ff:ff:ff:ff:ff"), timeout=5)	

      # real address
      if not ans:
	ans,unans = scapy.all.srp(scapy.all.Ether(src=self.mymac,dst="ff:ff:ff:ff:ff:ff")/scapy.all.ARP(psrc=self.myip,hwsrc=self.mymac,pdst=self.gw,hwdst="ff:ff:ff:ff:ff:ff"), timeout=5)	

      for snd,rcv in ans:
	hwaddr = rcv.sprintf(r"%Ether.src%")
	
      # check validity of the Gateway HwAddr (detected for ARP Spoofing Storm Attack) 
      try:
	ans,unans = scapy.all.srp(scapy.all.Ether(dst=hwaddr)/scapy.all.ARP(psrc="0.0.0.0",pdst="%s/%s" % (self.myip,self.cidr),hwdst=hwaddr), timeout=2)
      except:
	hwaddr = False
	
      if len(ans) > 1:
	self.logger.warning("MAC address detected for the Gateway: %s %s is not valid. It's indicated a ARP Spoofing/Poisoning Storm Attack !" % (self.gw,hwaddr))
        self.logger.error("Daemon Stopped.")
        # WINDOW: Invalid Gateway HwAddr !
	alert = Alert(0,"'Etherwall -  Invalid Gateway HwAddr !'","'Daemon Stopped: MAC address detected for the Gateway: \n%s %s is not valid. \nIts indicated a ARP Spoofing/Poisoning Storm Attack !'" % (self.gw,hwaddr))
	alert.start()
	sys.exit(1)
	
      if hwaddr:
	self.logger.info("MAC address detected for the Gateway: %s %s" % (self.gw,hwaddr))
      else:
	# fatal error will be stop the daemon
	self.logger.error("Couldn't obtain the gateway MAC address")
	self.logger.error("Daemon Stopped.")
	# WINDOW: Couldn't obtain the gateway MAC address !
	alert = Alert(0,"'Etherwall - Couldn't obtain the gateway MAC address !'","'Daemon Stopped: Couldn't obtain the gateway MAC address.'")
	alert.start()
	sys.exit(1)
      return hwaddr

    def _startEtherWall(self):
      """ Starting Etherwall """
      
      # adding router/gateway to ARP cache table as static ARP
      self.logger.info("Adding static entry for the Gateway: %s %s" % (self.gw, self.gwmac))
      if os.system("arp -s %s %s" % (self.gw, self.gwmac)):
	self.logger.error("Couldn't add the static entry for the Gateway")
  
      # starting arptables rules
      self.logger.info("Starting ARP Wall...")
      chain_start()
      # append gateway to chain
      app_gw_to_chain(gw=self.gw, mac=self.gwmac)
      # append another subnet/segment to chain
      app_another_subnet("%s/%s" % (self.myip,self.cidr))

      # after running ARP wall, adding the specified host to ARP cache tables as static ARP
      # and append host to chain.
      self.allow_host = []
      if (imp_allow_host()[0] == 0):
	if imp_allow_host()[1]:
	  for host in imp_allow_host()[1]:
	    if (host.split()[1] == ("%s" % (self.mymac)) or host.split()[1] == ("%s" % (self.gwmac))):
	      self.logger.critical("Forbidden: '%s': The MAC address same with your MAC & Gateway" % (host))
	    else:
	      self.allow_host.append(host)
	      self.logger.info("Adding static entry for the Host: %s" % (host))
	      if os.system("arp -s %s" % (host)):
		self.logger.error("Couldn't add the static entry for the Host")
	      else:
		# append host to chain 
		app_host_to_chain(ip=host.split()[0], mac=host.split()[1])
      else:
	# fatal error will be stoped the daemon
	self.logger.error(imp_allow_host()[1])
	self.logger.error("Daemon Stopped.")
	sys.exit(1)
      
      # sniffing mode
      if (self.promisc == "no"):
        self.logger.info("Device %s left promiscuous mode..." % (self.iface))
	scapy.all.conf.sniff_promisc = 0 
      else:
	self.logger.info("Device %s entered promiscuous mode..." % (self.iface))
  
      # starting realtime protection
      try:
	self.logger.info("Starting Realtime Protection...")
	# starting arp monitor
	arpmon = ArpMon(myip=self.myip, mymac=self.mymac, gw=self.gw, gwmac=self.gwmac, iface=self.iface, cidr=self.cidr, logger=self.logger, allow_host=self.allow_host)
	arpmon._startArpMon()
      except:
	if not check_if_up(iface=self.iface): # interface down
	  # WINDOW: interface error !
	  self.logger.error("Interface: The interface %s went down" % self.iface)
	  alert = Alert(0,"'Etherwall - Interface Error !'","'Daemon Stoped: The interface %s went down.'" % (self.iface))
	  alert.start()
        else:
	  # WINDOW: uknown error !
	  self.logger.error("Realtime Protection Failed")
	  alert = Alert(0,"'Etherwall - Realtime Protection Failed !'","'Daemon Stopped: Realtime Protection Stoped.'")
	  alert.start()
	self.logger.error("Daemon Stopped.")
	sys.exit(1)
	
## EOF ##