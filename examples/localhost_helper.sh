#!/bin/bash
#
# serverhelper script for running tests against knfsd running on localhost.
# Note that this requires that the running user can use sudo to restart nfsd
# without a password.
#

# server argument is ignored here
server=$1
command=$2
shift; shift

case $command in
reboot )
	sudo systemctl restart nfs-server.service
	;;
unlink )
	rm $1
	;;
rename )
	mv $1 $2
	;;
link )
	ln $1 $2
	;;
chmod )
	chmod $1 $2
	;;
esac
