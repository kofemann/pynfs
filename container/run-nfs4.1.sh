#!/bin/sh
#
cd /pynfs/nfs4.1
exec python3 -u ./testserver.py $*
