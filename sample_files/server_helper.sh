#!/bin/bash

# A simple script that can reboot a virtual guest using virsh, or unlink
# a file on the server. It would be used by adding
# --serverhelper=sample/server_helper.sh --serverhelperarg=SERVERNAME
# to testserver.py's commandline arguments, where SERVERNAME is
# something that works either as a libvirt domain or as a hostname to
# ssh to.

server=$1
command=$2
shift; shift

case $command in
reboot )
	virsh destroy $server
	virsh start $server
	;;
unlink )
	path=$1
	ssh $server "rm $1"
esac
