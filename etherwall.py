#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import time
from UnixDaemon import UnixDaemon
from etherWallService import etherWall
from NetMod import *
from GenWall import *

def help():
    """
      print usage
    """
    print ("Usage: %s {start|stop|restart|status}" % (sys.argv[0]))
    sys.exit(2)

if (__name__ == "__main__"):
    """
      Basic checking for user permissions.
    """
    if os.getuid():
      print ("[-] Operation not permitted, User must be root.")
      sys.exit(1)

    """
      Instance etherwall class
    """
    service = etherWall(pidfile = '/var/run/etherwall.pid',name='etherwall')

    if (len(sys.argv) == 2):
        if ('start' == sys.argv[1]):
            # start the daemon
            service.start()
            sys.exit(0)
        elif ('stop' == sys.argv[1]):
            # kill the daemon
            service.stop()
            # change the ARP tables rules, Inclusive -> Exclusive
            chain_stop()
            # flushing arp cache
            flush_arp_cache()
        elif ('restart' == sys.argv[1]):
            # restart the daemon
            service.restart()
        elif ('status' == sys.argv[1]):
            # check etherwall status
            if service.status():
                print ("Etherwall daemon is running...")
            else:
                print ("Etherwall daemon is not running, Please check logfile `/var/log/etherwall/etherwall.log' for more information.")
        else:
            help()
            sys.exit(0)
    else:
        help()

## EOF ##
