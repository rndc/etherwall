#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import threading

# Change working directory to the directory of Etherwall
scriptdir = os.path.dirname(sys.argv[0]) or '.'
os.chdir(scriptdir)

class Alert(threading.Thread):
	def __init__(self, title, message, msgbox):
		threading.Thread.__init__(self)
		self.status = 1 # 1 = WARNING
		self.title = title
		self.message = message
		self.msgbox = msgbox
		self.sctdir = scriptdir 

	def run(self):
		if (self.msgbox == 'yes'):
			os.popen("%s/MsgBox.py %s %s %s &" % (self.sctdir, self.status, self.title, self.message))

## EOF ##
