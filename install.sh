#!/bin/bash
#
# This file is part of Etherwall
# Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
# This program is published under a GPLv3 license

# check if we're root
if [ "$(whoami)" != "root" ]; then
  echo "Error: you need to be root to install etherwall"
  exit 1
fi

# ask for confirmation
echo -n "Are you sure you want install etherwall?[y/n] "
read cek
if [ "$cek" != "y" -a "$cek" != "Y" ]; then
  echo "Installation aborted."
  exit 1
fi

# show the license
more doc/COPYING
echo -n "Do you agree with the license?[y/n] "
read cek
if [ "$cek" != "y" -a "$cek" != "Y" ]; then
  echo "Installation aborted."
  exit 1
fi

# checking dependencies
for d in ifconfig tcpdump arp; do
  if [ "$(whereis $d | awk '{print $2}')" = "" ]; then
    echo "Error: $d not installed."
    exit 1
  fi
done

if [ "$(whereis arptables | awk '{print $2}')" = "" ]; then
  if [ "$(whereis curl | awk '{print $2}')" = "" ]; then
    echo "Error: curl not found. Cannot download arptables"
    exit 1
  fi
  curl -L -o /tmp/arptables-v0.0.3-4.tar.gz  "http://sourceforge.net/projects/ebtables/files/arptables/arptables-v0.0.3/arptables-v0.0.3-4.tar.gz/download"

  if [ "$(whereis gcc | awk '{print $2}')" = "" -o "$(whereis make | awk '{print $2}')" = "" ]; then
    echo "Error: cannot find GNU compiler"
    exit 1
  fi

  CWD=`pwd`
  cd /tmp
  tar -zxvf arptables-v0.0.3-4.tar.gz && cd arptables-v0.0.3-4
  make && make install
  ln -s /usr/local/sbin/arptables /usr/sbin
  ln -s /usr/local/sbin/arptables-restore /usr/sbin
  ln -s /usr/local/sbin/arptables-save /usr/sbin
  cd .. && rm -r arptables-v0.0.3-4*
  cd $CWD
fi

# creating etherwall installation directory and start copying files
echo "Creating etherwall installation directory and copying files..."
mkdir /opt/etherwall
cp -r * /opt/etherwall
rm /opt/etherwall/{install.sh,uninstall.sh}

# create etherwall control script
echo "Creating etherwall script..."
cat << EOF > /sbin/etherwall
#!/bin/bash
#
# This file is part of Etherwall
# Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
# This program is published under a GPLv3 license
#
# Provides: etherwall
# Short-Description: Start/stop the etherwall network security daemon
# Description: Controls the main etherwall network security daemon "etherwall.py"

path_script="/opt/etherwall/etherwall.py"
case \$1 in
  'start')
    \$path_script start
    ;;
  'stop')
    \$path_script stop
    ;;
  'restart')
    \$path_script restart
    ;;
  'status')
    \$path_script status
    ;;
  *)
    echo "Usage: etherwall {start|stop|restart|status}"
    exit 1
    ;;
esac
EOF
chmod +x /sbin/etherwall

# create etherwall console script
echo "Creating etherwall console script..."
cat << EOF > /sbin/ethwconsole
#!/bin/bash
#
# This file is part of Etherwall
# Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
# This program is published under a GPLv3 license
#
# Provides: ethwconsole
# Short-Description: Command interactive program of etherwall
# Description: This script is a command etherwall interactive programs to communicate with
#              the daemon etherwall, and provide useful tools related to data link layer.

/opt/etherwall/ethwconsole.py
EOF
chmod +x /sbin/ethwconsole

# copying configuration files
echo "Copying etherwall configuration files..."
cp -r config /etc/etherwall

# copying manual file
echo "Copying manual pages..."
cp doc/*.gz /usr/share/man/man8
chmod +r /usr/share/man/man8/{etherwall.8.gz,etherwall-id.8.gz,ethwconsole.8.gz,ethwconsole-id.8.gz}

# setting executable flags
echo "Setting executable flags..."
chmod +x -R /opt/etherwall/{etherwall.py,ethwconsole.py,MsgBox.py,tool}

# all done
echo "Installation finished. Type 'etherwall' or 'ethwconsole' as root to run etherwall."
