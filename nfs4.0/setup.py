#!/usr/bin/env python3

from __future__ import print_function
from __future__ import absolute_import
import sys
from distutils.core import setup, Extension
from distutils.dep_util import newer_group
import os
import glob
try:
    import xdrgen
except ImportError:
    import use_local
    import xdrgen

DESCRIPTION = """\
pynfs is a collection of tools and libraries for NFS4. It includes
a NFS4 library and a server test application.
"""

topdir = os.getcwd()
if  __name__ == "__main__":
    if os.path.isfile(os.path.join(topdir, 'lib', 'testmod.py')):
        sys.path.insert(1, os.path.join(topdir, 'lib'))

def needs_updating(xdrfile):
    name_base = xdrfile[:xdrfile.rfind(".")]
    sources = [xdrfile]
    targets = [ name_base + "_const.py",
                name_base + "_type.py",
                name_base + "_pack.py" ]
    for t in targets:
        if newer_group(sources, t):
            return True
    return False

def use_xdr(dir, xdrfile):
    """Move to dir, and generate files based on xdr file"""
    os.chdir(dir)
    if needs_updating(xdrfile):
        xdrgen.run(xdrfile)
        for file in glob.glob(os.path.join(dir, 'parse*')):
            print("deleting", file)
            os.remove(file)

def generate_files():
    home = os.getcwd()
    use_xdr(os.path.join(topdir, 'xdrdef'), 'nfs4.x')
    use_xdr(os.path.join(topdir, 'xdrdef'), 'nfs3.x')

    dir = os.path.join(topdir, 'lib', 'rpc')
    use_xdr(dir, 'rpc.x')

    dir = os.path.join(topdir, 'lib', 'rpc', 'rpcsec')
    use_xdr(dir, 'gss.x')
    os.chdir(home)

# FRED - figure how to get this to run only with build/install type command
generate_files()

from testserver import VERSION
setup(name = "newpynfs",
      version = VERSION,
      license = "GPL",
      description = "Python NFS4 tools",
      long_description = DESCRIPTION,
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",

      package_dir = {'': 'lib'},
      packages = ['servertests', 'rpc', 'rpc.rpcsec'],
      py_modules = ['testmod'],
      scripts = ['testserver.py', 'showresults.py']
      )

PATHHELP = """\

See http://www.python.org/doc/current/inst/search-path.html for detailed
information on various ways to set the search path.
One easy way is to set the environment variable PYTHONPATH.
"""
if "install" in sys.argv:
    print(PATHHELP)
