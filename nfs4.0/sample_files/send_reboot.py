#!/usr/bin/python

import sys
import os

"""
A simple reboot script for the reboot tests that reboots a virtual guest.
It would be used by adding
--rebootscript=sample/send_reboot.py --rebootargs=SERVERNAME
to testserver.py's commandline arguments.
"""

def reboot(servername):
    os.system('virsh destroy ' + servername)
    os.system('virsh start ' + servername)

reboot(sys.argv[1])
