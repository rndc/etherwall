#!/usr/bin/env python
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

import os
import sys
import atexit
import random
import rlcompleter
import readline
import subprocess
import NetMod
import scapy.all

# Change working directory to the directory of Etherwall
scriptdir = os.path.dirname(sys.argv[0]) or '.'
os.chdir(scriptdir)

try:
  __author__ 	= 'Agus Bimantoro <l0g.bima@gmail.com>'   # Author
  __version__	= open('doc/VERSION').read().strip()      # Version
  __release__	= open('doc/RELEASE').read().strip()      # Release
except IOError:
  __author__	= 'Agus Bimantoro <l0g.bima@gmail.com>'   
  __version__	= open('/opt/etherwall/doc/VERSION').read().strip()
  __release__	= open('/opt/etherwall/doc/RELEASE').read().strip()


HIS_FILE	= '~/.etherwall_history'     # History File Name
PLUG_PATH	= 'tool'                     # Plugin/Tool Path Name
ETHW_BANNER	= [                          # banner
"""          
       _                                  _ _
      | |   _                            | | |
  ____| |_ | | _   ____  ____ _ _ _  ____| | |
 / _  )  _)| || \\ / _  )/ ___) | | |/ _  | | |
( (/ /| |__| | | ( (/ /| |   | | | ( ( | | | |
 \\____)\\___)_| |_|\\____)_|    \\____|\\_||_|_|_|

+ Etherwall %s [%s]
+ Author by %s 
+ Copyright (C) %s - RNDC <http://rndc.or.id> 
+ Please type \033[4mhelp\033[0m for more information.\n""" % (__version__,__release__,__author__,__release__[-4:]),

"""
      __    {Etherwall %s} 
    .'  `./
    |a_a  |  - PtP Protection 
    \\<_)__/  - PtM Protection 
    /(   )\\  - Realtime Protection
   |\`> < /\\ - Early Warning
   \\_|=='|_/\n""" % (__version__),
    
"""
             .-.
            (o o)  Etherwall %s 
  +-----oooO-(_)----------------+
  |                             |
  | ARP Daemon Handler          |
  | to Protect Your System      |
  | from ARP Spoofing/Poisoning |
  |                             |
  +-----------------Ooo---------+
	   |__|__|
	    || || 
	  ooO Ooo\n""" % (__version__),
	  
"""
          .
       _.:::._
  . .-`   '   `-. .
  :`  .: ARP :.  `: 
  |               |                 
  |   [ ]   [ ]   | {Etherwall %s}        
  | o--'--+--'--o |
  :      [ ]      :                                      
   \             /
    `.    .    .`
      `-.:::.-`
	  '\n""" % (__version__)]
      

class ethwconsole():
	def complete(self, lines,state):
		"""
			Command completer
			http://docs.python.org/library/rlcompleter.html
		"""
		command = ['quit']
		try:
			for files in os.listdir(PLUG_PATH):
				if len(files.split(".")) != 2:
					command.append(files)
		except OSError:
			print ("[-] No such directory: %s" % (PLUG_PATH))

		results = [x + " " for x in command if x.startswith(lines)] + [None]
		return results[state]
		
	def rhistory(self):
		"""
			Load/Read history
			http://docs.python.org/tutorial/interactive.html
		"""
		self.history_path = os.path.expanduser(HIS_FILE)
		if os.path.exists(self.history_path):
			readline.read_history_file(self.history_path)

	def shistory(self):
		"""
			Save history
			http://docs.python.org/tutorial/interactive.html
		"""
		readline.write_history_file(self.history_path)

	def check_etherwall_pid(self):
		"""
			Check the etherwall daemon process
		"""
      
		# check pid
		try:
			pf=file("/var/run/etherwall.pid",'r')
			pid = int(pf.read().strip())
		except IOError:
			print ("\nWARNING: Etherwall daemon is not running, Some plugin or command maybe is not work.\n") 
			return
		
		# check proc
		try:
			procfile = file("/proc/%d/status" % (pid), 'r')
			procfile.close()
		except IOError:
			print ("\nWARNING: Etherwall daemon is not running, Some plugin or command maybe is not work.\n")

	def main(self):
		# command completer
		readline.set_completer(self.complete)
		readline.parse_and_bind("tab: complete")
		
		# load command history
		self.rhistory()
		
		# banner ASCI Art
		print ETHW_BANNER[random.randint(0,len(ETHW_BANNER)-1)]
		
		# check etherwall PID
		self.check_etherwall_pid()
		
		# simple python prompt interactive programs
		while True:
			try:
				cmdin = raw_input("\033[4methw\033[0m > ")
				cmdin = cmdin.strip()
				if  (cmdin == ("")):
					continue
				elif (cmdin.split()[0] == ("quit")):
					print ("")
					atexit.register(self.shistory)
					sys.exit(0)
				# run the command
				cmdrun = subprocess.call("tool/%s 2> /dev/null" % (cmdin), shell=True)
				if (cmdrun == 1): # error execute (plugin/script error)
					print ("\n[-] Error: In the script '%s'.\n" % (cmdin.split()[0]))
				elif (cmdrun == 126):
					print ("\n[-] Error: %s: Permission denied\n" % (cmdin))
				elif (cmdrun == 127):
					print ("\n[-] Error: %s: Uknown command\n" % (cmdin)) 
			except KeyboardInterrupt:
				print ("\n\nType 'quit' for exit\n")
			except EOFError:
				print ("\n\nType 'quit' for exit\n")
		
if (__name__=="__main__"):
	"""
		Basic checking for user permissions.
	"""
	if os.getuid():
		print ("[-] Operation not permitted, User must be root.")
		sys.exit(1)
	
	ethw = ethwconsole()
	ethw.main()

## EOF ##
