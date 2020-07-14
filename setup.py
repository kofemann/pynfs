#!/usr/bin/env python3

from __future__ import print_function

from distutils.core import setup

import sys
import os
from os.path import join

DESCRIPTION = """
pynfs
============

Add stuff here.
"""

DIRS = ["xdr", "rpc", "nfs4.1", "nfs4.0"] # Order is important

def setup(*args, **kwargs):
    cwd = os.getcwd()
    command = " ".join(sys.argv)
    for dir in DIRS:
        print("\n\nMoving to %s" % dir )
        os.chdir(join(cwd, dir))
        os.system("python%s %s" % (sys.version[0], command))
    os.chdir(cwd)

setup(name = "pynfs",
      version = "0.0.0", # import this?
      packages = ["nfs4", "rpc", "xdr"],
      description = "NFS tools, tests, and support libraries",
      long_description = DESCRIPTION,
      #install_requires = ["gssapi", "ply"],

      # These will be the same
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",
      url = "http://www.citi.umich.edu/projects/nfsv4/pynfs/",
      license = "GPL"
      
      )

