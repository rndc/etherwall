#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import sys
import gtk
import gobject

# close windows automatically in */seconds
TIME_OUT = 10

class MsgBox():
	def __init__(self,  status, title, message):
		""" Windows box to message end user if spoofing/poisoning attacks detected or if an error occurs in a daemon process """
		self.status = int(status)
		self.title = title
		self.message = message
		self.timeout = TIME_OUT
		
		# set window box
		self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.set_position(gtk.WIN_POS_CENTER)
		
		# self.window.set_icon_from_file("etherwall.png")
		self.window.set_size_request(540, 100)
		self.window.set_resizable(False)
		self.window.set_title(self.title)
		
		# put label & image to window box
		self.label = gtk.Label(self.message)
		self.image = gtk.Image()
		
		# 0 = error, 1 = warning
		if (self.status==1):
			self.image.set_from_stock(gtk.STOCK_DIALOG_WARNING, gtk.ICON_SIZE_DIALOG)
		else:
			self.image.set_from_stock(gtk.STOCK_DIALOG_ERROR, gtk.ICON_SIZE_DIALOG)
		
		self.h = gtk.HBox()
		self.h.pack_start(self.image)
		self.h.pack_start(self.label)
		self.window.add(self.h)
		
		# closed
		self.window.connect('destroy', lambda q: gtk.main_quit())
		
		# show all 
		self.window.show_all()
		
		# start timer
		self.counter = 0
		
		# closing by time
		# set periodic timer = 1
		gobject.timeout_add_seconds(1, self.timer)
	
	def timer(self):
		self.counter += 1
		if (self.counter == self.timeout):
			gtk.main_quit()
		elif (self.counter > self.timeout):
			gtk.main_quit()
		return True
	
	def main(self):
		gtk.main()

if (len(sys.argv) == 4):
	msg=MsgBox(sys.argv[1], sys.argv[2], sys.argv[3])
	msg.main()

## EOF ##
