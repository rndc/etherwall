#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import signal
from GenWall import chain_stop
from NetMod import flush_arp_cache

# Change working directory to the directory of Etherwall
scriptdir = os.path.dirname(sys.argv[0]) or '.'
os.chdir(scriptdir)

def Error(title, message, logger):
	""" Handling Runtime Error """
	status = 0 # 0 = Error
	title = title
	message = message
	logger = logger
	pidfile = "/var/run/etherwall.pid"
	sctdir = scriptdir 

	os.popen("%s/MsgBox.py %s %s %s &" % (sctdir, status, title, message))
	
	# if an error occurs in a daemon process, reset all rules & stopping the daemon.
	# saved into logfile
	logger.error(message.strip("'"))
	logger.error("Daemon Stopped.")
			
	# reset rules
	chain_stop()
	
	# flushing arp cache
	flush_arp_cache()
			
	# kill service
	pf = file(pidfile, 'r')
	pid = int(pf.read().strip())
	pf.close()
	os.remove(pidfile)
	while True:
		os.kill(pid, signal.SIGTERM)
		time.sleep(0.1)

## EOF ##
