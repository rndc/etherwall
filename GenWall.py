#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os

""" 
generate ARPtables rules
"""

# append the gateway to chain
def app_gw_to_chain(gw=None, mac=None):
    if os.system("arptables -A INPUT -s %s --source-mac %s -j ACCEPT" % (gw, mac)):
      os.system("arptables -A IN -s %s --source-mac %s -j ACCEPT" % (gw, mac))
    if os.system("arptables -A OUTPUT -d %s -j ACCEPT" % gw):
      os.system("arptables -A OUT -d %s -j ACCEPT" % gw)
      
# append the another host to chain
def app_host_to_chain(ip=None, mac=None):
    if os.system("arptables -A INPUT -s %s --source-mac %s -j ACCEPT" % (ip, mac)):
      os.system("arptables -A IN -s %s --source-mac %s -j ACCEPT" % (ip, mac))
    if os.system("arptables -A OUTPUT -d %s -j ACCEPT" % ip):
      os.system("arptables -A OUT -d %s -j ACCEPT" % ip)
      
# delete the host from chain
def del_host_from_chain(ip=None, mac=None):
    if os.system("arptables -D INPUT -s %s --source-mac %s -j ACCEPT" % (ip, mac)):
      os.system("arptables -D IN -s %s --source-mac %s -j ACCEPT" % (ip, mac))
    if os.system("arptables -D OUTPUT -d %s -j ACCEPT" % ip):
      os.system("arptables -D OUT -d %s -j ACCEPT" % ip)
    
# allow another subnet/segment
def app_another_subnet(ip=None):
    if os.system("arptables -A INPUT -s ! %s -j ACCEPT" % (ip)):
      os.system("arptables -A IN -s ! %s -j ACCEPT" % (ip))
    if os.system("arptables -A OUTPUT -d ! %s -j ACCEPT" % (ip)):
      os.system("arptables -A OUT -d ! %s -j ACCEPT" % (ip))
	
# policy on (Inclusive firewall)
def chain_start():
    os.system("arptables -F")
    if os.system("arptables -P INPUT DROP"):
      os.system("arptables -P IN DROP")
    if os.system("arptables -P OUTPUT DROP"):
      os.system("arptables -P OUT DROP")

# policy off (Exclusive firewall)
def chain_stop():
    os.system("arptables -F")
    if os.system("arptables -P INPUT ACCEPT 2> /dev/null"):
      os.system("arptables -P IN ACCEPT")
    if os.system("arptables -P OUTPUT ACCEPT 2> /dev/null"):
      os.system("arptables -P OUT ACCEPT")

## EOF ##
