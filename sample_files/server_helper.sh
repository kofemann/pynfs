#!/bin/bash

# A simple script for the reboot tests that reboots a virtual guest.
# It would be used by adding
# --serverhelper=sample/send_reboot.py --serverhelperarg=SERVERNAME
# to testserver.py's commandline arguments.

server=$1
command=$2
shift; shift

case $command in
reboot )
	virsh destroy $server
	virsh start $server
	;;
esac
