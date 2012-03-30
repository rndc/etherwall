#!/bin/bash
#
# This file is part of Etherwall
# Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
# This program is published under a GPLv3 license

if [ "$(whoami)" != "root" ]; then
  echo "Error: you need to be root to remove etherwall"
  exit 1
fi

echo -n "Are you sure you want to remove etherwall?[y/n] "
read cek
if [ "$cek" != "y" -a "$cek" != "Y" ]; then
  echo "Uninstallation aborted."
  exit 1
fi

if [ ! -d "/opt/etherwall" ]; then
  echo "Error: etherwall is not installed on your system."
  exit 1
fi

echo "Removing etherwall installation directory..."
rm -r /opt/etherwall

echo "Removing etherwall configuration directory..."
rm -r /etc/etherwall 2> /dev/null

echo "Removing etherwall log directory..."
rm -r /var/log/etherwall

echo "Removing etherwall scripts..."
rm /sbin/{etherwall,ethwconsole} 2> /dev/null

echo "Removing etherwall manual pages..."
  rm /usr/share/man/man8/{etherwall.8.gz,etherwall-id.8.gz,ethwconsole.8.gz,ethwconsole-id.8.gz} 2> /dev/null

echo "All done..."
