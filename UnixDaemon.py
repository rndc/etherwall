#!/usr/bin/env python
#
# This is a program for unix and linux daemon in python language, 
# See information about the original code at
# http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
#
# NOTE:
# This source code has been modified, Thanks to Sander Marechal(www.jejik.com) for this code.. :)
# This program is published under a GPL License

import os
import sys
import time
import atexit
import logging
import signal

class UnixDaemon:
	"""
		A generic daemon class.
		Usage: subclass the Daemon class and override the run() method
	"""
	
	def __init__(self, pidfile,name='UnixDaemon', stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
		self.stdin = stdin
		self.stdout = stdout
		self.stderr = stderr
		self.pidfile = pidfile
		self.name = name
		
		# unix and linux daemon log
		if not os.path.exists("/var/log/%s" % name):
			os.mkdir("/var/log/%s" % name)
		logger = logging.getLogger(name)
		handler = logging.FileHandler("/var/log/%s/%s.log" % (name,name))
		formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
		handler.setFormatter(formatter)
		logger.addHandler(handler)
		logger.setLevel(logging.INFO)
		self.logger = logger
	
	def daemonize(self):
		"""
			do the UNIX double-fork magic, see Stevens' "Advanced
			Programming in the UNIX Environment" for details (ISBN 0201563177)
			http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
		"""
		
		try:
			pid = os.fork()
			if (pid > 0):
				# exit first parent
				sys.exit(0)
		except OSError, e:
			sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1)
		
		# decouple from parent environment
		os.chdir("/")
		os.setsid()
		os.umask(0)
		
		# do second fork
		try:
			pid = os.fork()
			if (pid > 0):
				# exit from second parent
				sys.exit(0)
		except OSError, e:
			sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(1)
		
		# redirect standard file descriptors
		sys.stdout.flush()
		sys.stderr.flush()
		si = file(self.stdin, 'r')
		so = file(self.stdout, 'a+')
		se = file(self.stderr, 'a+', 0)
		os.dup2(si.fileno(), sys.stdin.fileno())
		os.dup2(so.fileno(), sys.stdout.fileno())
		os.dup2(se.fileno(), sys.stderr.fileno())
		
		# write pidfile
		atexit.register(self.delpid)
		pid = str(os.getpid())
		file(self.pidfile, 'w+').write("%s\n" % pid)
		self.run()
	
	def delpid(self):
		os.remove(self.pidfile)
	
	def start(self):
		"""
			Start the daemon
		"""
		
		# Check for a pidfile to see if the daemon already runs
		try:
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			self.logger.info("Starting Daemon...")
			sys.stdout.write("Starting %s daemons...\n" % self.name)
			pid = None
		
		if pid:
			message = "pidfile `%s' already exist. Daemon already running?\n"
			sys.stderr.write(message % self.pidfile)
			sys.exit(1)
		
		# start the daemon
		self.daemonize()
	
	def stop(self):
		"""
			Stop the daemon
		"""
		
		# get the pid from the pidfile
		try:
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			pid = None
		
		if not pid:
			message = "pidfile `%s' does not exist. Daemon not running?\n"
			sys.stderr.write(message % self.pidfile)
			return # not an error in a restart
		
		# try killing the daemon process
		try:
			sys.stdout.write("Stopping %s daemons...\n" % self.name)
			while 1:
				os.kill(pid, signal.SIGTERM)
				time.sleep(0.1)
		except OSError, err:
			err = str(err)
			if err.find("No such process") > 0:
				if os.path.exists(self.pidfile):
					os.remove(self.pidfile)
				else:
					print str(err)
					sys.exit(1)
					
		self.logger.info("Daemon Stopped.")
	
	def restart(self):
		"""
			Restart the daemon
		"""
		self.stop()
		self.start()
	
	def status(self):
		"""
			Check for daemon status
		"""
		try:
			pf = file(self.pidfile, 'r')
			pid = int(pf.read().strip())
			pf.close()
		except IOError:
			pid = None
		
		if not pid:
			# pid file doesn't exist
			return False
		
		try:
			procfile = file("/proc/%d/status" % pid, 'r')
			procfile.close()
		except IOError:
			# there isn't a process with the PID specified
			return False
		return True
	
	def run(self):
		"""
			You should override this method when you subclass Daemon. It will be called after the process has been
			daemonized by start() or restart().
		"""
		raise NotImplementedError
		
		   
## EOF ##
