#!/bin/bash
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

who_uninstall=`whoami`

function main {
echo -e "Uninstalling etherwall:\n"

echo "Removing etherwall installation directory..."
rm -r /opt/etherwall

echo "Removing etherwall configuration directory..."
rm -r /etc/etherwall 2> /dev/null

echo "Removing etherwall log directory..."
rm /var/log/etherwall/etherwall.log

echo "Removing etherwall script program..."
rm /sbin/etherwall 2> /dev/null

echo "Removing ethwconsole script program..."
rm /sbin/ethwconsole 2> /dev/null

echo "Removing etherwall manual page..."
rm /usr/share/man/man8/etherwall.8.gz 2> /dev/null
rm /usr/share/man/man8/etherwall-id.8.gz 2> /dev/null
rm /usr/share/man/man8/ethwconsole.8.gz 2> /dev/null
rm /usr/share/man/man8/ethwconsole-id.8.gz 2> /dev/null

echo -e "\nUninstallation finished."
}

if [ "$who_uninstall" == "root" ]; then
        echo -n -e "Are you sure you want to remove/uninstall etherwall [Y/n]? "
	read persetujuan
	if [ "$persetujuan" == "Y" ] || [ "$persetujuan" == "y" ]; then		
		if [ -d "/opt/etherwall/" ]; then 
			main
		else
			echo -e "\nError: Etherwall program is not installed on your system"
			exit 1
		fi
	else
		exit 0
	fi
else
	echo -e "Error: Cannot remove/uninstall etherwall,\n       it may require superuser privileges (eg. root)."
	exit 1
fi
