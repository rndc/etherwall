#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import signal
import threading
from NetMod import get_if_conf
from GenWall import chain_stop

# Change working directory to the directory of Etherwall
scriptdir = os.path.dirname(sys.argv[0]) or '.'
os.chdir(scriptdir)

class Alert(threading.Thread):
	def __init__(self, status, title, message, logger):
		threading.Thread.__init__(self)
		self.status = status # ERROR = 0, WARNING = 1
		self.title = title
		self.message = message
		self.logger = logger
		self.pidfile = "/var/run/etherwall.pid"
		self.sctdir = scriptdir 

	def run(self):
		os.popen("%s/MsgBox.py %s %s %s &" % (self.sctdir, self.status, self.title, self.message))
		# if an error occurs in a daemon process, reset all rules & stopping the daemon.
		if not self.status:
			# saved into logfile
			self.logger.error(self.message.strip("'"))
			self.logger.error("Daemon Stopped.")
			
			# reset rules
			chain_stop()
			# flushing arp cache
			flush_arp_cache()
			
			# kill service
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
			os.remove(self.pidfile)
			while True:
				os.kill(pid, signal.SIGTERM)
				time.sleep(0.1)

## EOF ##
