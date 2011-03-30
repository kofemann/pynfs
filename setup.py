from distutils.core import setup

import sys
import os
from os.path import join

DESCRIPTION = """
newpynfs 4.1
============

Add stuff here.
"""

DIRS = ["ply", "xdr", "gssapi", "rpc", "nfs4.1"] # Order is important

def setup(*args, **kwargs):
    print "This just runs the setup.py file in each of the following dirs:"
    print DIRS
    print "If you want more control, say no and do it by hand"
    str = raw_input("Continue? (y/n) ")
    if (not str) or str[0] not in ['y', 'Y']:
        return
    cwd = os.getcwd()
    command = " ".join(sys.argv)
    for dir in DIRS:
        print "\n\nMoving to %s" % dir 
        os.chdir(join(cwd, dir))
        os.system("python %s" % command)
    os.chdir(cwd)

setup(name = "pynfs",
      version = "0.0.0", # import this?
      packages = ["nfs4", "rpc", "xdr", "ply", "gssapi"], 
      description = "NFS tools, tests, and support libraries",
      long_description = DESCRIPTION,
      
      # These will be the same
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",
      url = "http://www.citi.umich.edu/projects/nfsv4/pynfs/",
      license = "GPL"
      
      )

