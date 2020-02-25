#!/bin/bash

# A simple script that can restart knfsd, or unlink
# a file on the server. It would be used by adding
# --serverhelper=sample/server_helper.sh --serverhelperarg=SERVERNAME
# to testserver.py's commandline arguments.

server=$1
command=$2
shift; shift

case $command in
reboot )
	# This would maybe more interesting; note server would have to
	# work either as a libvirt domain or as a hostname to ssh to:
	#   virsh destroy $server
	#   virsh start $server
	# But just restarting knfsd is faster.  Also the full reboot was
	# interfering with my testing because I had a very short lease
	# period set, I was waiting for ssh to come up to decide when
	# the boot was done, and ssh wasn't coming up till the lease
	# period was done.
	ssh root@$server "systemctl restart nfs-server.service"
	;;
unlink )
	ssh $server "rm $1"
	;;
rename )
	ssh $server "mv $1 $2"
	;;
link )
	ssh $server "ln $1 $2"
	;;
chmod )
	ssh $server "chmod $1 $2"
	;;
esac
