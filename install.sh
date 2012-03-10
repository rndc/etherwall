#!/bin/bash
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license

who_install=`whoami`

function etherwall_ctl_script {
echo '#!/bin/bash
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license
#
#  Provides: etherwall
#  Short-Description: Start/stop the etherwall network security daemon
#  Description: Controls the main etherwall network security daemon "etherwall.py"

path_script="/opt/etherwall/etherwall.py"
case $1 in 
	'start')
	start="$path_script start"
	$start
	;;
	'stop')
	stop="$path_script stop"
	$stop
	;;
	'restart')
	restart="$path_script restart"
	$restart
	;;
	'status')
	status="$path_script status"
	$status
	;;
	*)
	echo "Usage: etherwall {start|stop|restart|status}"
	exit 1
	;;
esac
' > etherwall
}


function etherwall_console_script {
echo '#!/bin/bash
#
#  This file is part of Etherwall
#  Copyright (C) Agus Bimantoro <l0g.bima@gmail.com>
#  This program is published under a GPLv3 license
#
#  Provides: ethwconsole
#  Short-Description: Command interactive program of etherwall
#  Description: This script is a command etherwall interactive programs to communicate with
#               the daemon etherwall, and provide useful tools related to data link layer.

path_script="/opt/etherwall/ethwconsole.py"

$path_script' > ethwconsole
}

function install_arptables {
arptables_link="http://sourceforge.net/projects/ebtables/files/arptables/arptables-v0.0.3/arptables-v0.0.3-4.tar.gz/download"

# downloading arptables
c_url=$(whereis curl | awk '{print $2}')
if [ "$c_url" != "" ]; then 
  echo -n -e "\nDownloading Arptables from $arptables_link\n\n"
  curl -L -o /tmp/arptables-v0.0.3-4.tar.gz $arptables_link
  echo -n -e "\nDownload Complete !, File saved in /tmp/arptables-v0.0.3-4.tar.gz\n"
else
  echo -n -e "\nError: Download Failed, The CURL program not found. Please download arptables manually\n"
  exit 1
fi

# installing arptables
gnu_c=$(whereis gcc | awk '{print $2}')
gnu_make=$(whereis make | awk '{print $2}')
if [ "$gnu_c" != "" ]; then 
  if [ "$gnu_make" != "" ]; then
    echo -n -e "\nInstalling arptables...\n\n"
    tar -zxf /tmp/arptables-v0.0.3-4.tar.gz 
    cd arptables-v0.0.3-4
    make && make install
    ln -s /usr/local/sbin/arptables/arptables /usr/sbin  
    ln -s /usr/local/sbin/arptables/arptables-restore /usr/sbin
    ln -s /usr/local/sbin/arptables/arptables-save /usr/sbin        
    cd ..
    rm -r arptables-v0.0.3-4
  else
    echo -n -e "\nError: Compile Failed, The GNU MAKE program not found\n"
    exit 1
  fi
else
  echo -n -e "\nError: Compile Failed, The GNU C program not found\n"
  exit 1
fi
}

function check_dependencies {
echo "Checking dependencies..."

# Arptables
arpTables=$(whereis arptables | awk '{print $2}')
if [ "$arpTables" == "" ]; then
  echo "Error: The depedencies 'arptables' not installed"
  echo -n -e "\nDo you want to install arptables [Y/n]? "
  read lanjut
  if [ "$lanjut" == "Y" ] || [ "$lanjut" == "y" ]; then 
    install_arptables
  else
    exit 0
  fi
fi

# Tcpdump
tcpDump=$(whereis tcpdump | awk '{print $2}')
if [ "$tcpDump" == "" ]; then
  echo -n -e "Error: The depedencies 'tcpdump' not installed\n"
  exit 1
fi

# Arp
arpUnix=$(whereis arp | awk '{print $2}')
if [ "$arpUnix" == "" ]; then
  echo -n -e "Error: The depedencies 'arp' not installed\n"
  exit 1
fi

# Ifconfig
ifUnix=$(whereis ifconfig | awk '{print $2}')
if [ "$ifUnix" == "" ]; then
  echo -n -e "Error: The depedencies 'ifconfig' not installed\n"
  exit 1
fi
}

function main {
echo -e "Installing etherwall:\n"

# checking dependencies
check_dependencies

# creating etherwall installation directory
echo "Creating etherwall installation directory..."
mkdir /opt/etherwall

# copying all file
echo "Copying all file to '/opt/etherwall'"
cp -r * /opt/etherwall
rm /opt/etherwall/install.sh
rm /opt/etherwall/uninstall.sh

# creating etherwall file
echo "Creating etherwall file..."
touch etherwall
etherwall_ctl_script

# copying etherwall program to /sbin
echo "Copying etherwall program to '/sbin'"
chmod u+x etherwall
mv etherwall /sbin/etherwall

# creating ethwconsole file
echo "Creating ethwconsole file..."
touch ethwconsole
etherwall_console_script

# copying ethwconsole program to /sbin
echo "Copying ethwconsole program to '/sbin'"
chmod u+x ethwconsole
mv ethwconsole /sbin/ethwconsole

# copying etherwall file configuration to /etc
echo "Copying etherwall file configuration to '/etc'"
cp -r config /etc/etherwall

# copying etherwall manual page to /usr/share/man/man8
echo "Copying etherwall manual pages to '/usr/share/man/man8'"
cp doc/*.gz /usr/share/man/man8

# set executable flag
echo "Chmod u+x /opt/etherwall/etherwall.py"
chmod u+x /opt/etherwall/etherwall.py
echo "Chmod u+x /opt/etherwall/ethwconsole.py"
chmod u+x /opt/etherwall/ethwconsole.py
echo "Chmod u+x /opt/etherwall/MsgBox.py"
chmod u+x /opt/etherwall/MsgBox.py
echo "Chmod u+x -R /opt/etherwall/tool"
chmod u+x -R /opt/etherwall/tool

echo -e "\nInstallation finished. Type etherwall or ethwconsole as root to run.\n"

exit 0
}

if [ "$who_install" == "root" ]; then
	echo -n -e "Are you sure you want to install etherwall [Y/n]? "
	read lanjut
	if [ "$lanjut" == "Y" ] || [ "$lanjut" == "y" ]; then	
		echo -n -e "\nType \033[4menter\033[0m to read the license of etherwall..."
		read 
		more doc/COPYING
                loops="True"
                while [ $loops == "True" ]; do
		  echo -n -e "\nDo you aggree [Y/n]? "
		  read setuju
		  if [ "$setuju" == "Y" ] || [ "$setuju" == "y" ]; then	
			main
		  elif [ "$setuju" == "N" ] || [ "$setuju" == "n" ]; then
			exit 0
		  fi
                done
	else
		exit 0
	fi
else
	echo -e "Error: Cannot install etherwall,\n       it may require superuser privileges (eg. root)."
	exit 1
fi
