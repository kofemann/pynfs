#!/bin/sh
#
cd /pynfs/nfs4.0
exec python3 -u ./testserver.py $*
