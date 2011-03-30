#!/usr/bin/env python

from distutils.core import setup, Extension

DESCRIPTION = """
gssapi
======

This is a Python wrapping (using SWIG) of the C gssapi library.
It is based on RFC 2743.  However, instead of mapping the calls
directly, Python class structures are used to greatly simplify
the interface.  In particular, cleanup of allocated structures
is handled automatically, and inquiry calls are replaced by
inspecting class attributes.
"""

# SWIG needs to be run to generate gssapi.py, *BEFORE* we copy gssapi.py
from distutils.command.build import build as _build

class build(_build):
    """Specialized Python source builder."""
    # re-order the sub-commands so build_py is called last
    sub_commands = [('build_clib',    _build.has_c_libraries),
                    ('build_ext',     _build.has_ext_modules),
                    ('build_scripts', _build.has_scripts),
                    ('build_py',      _build.has_pure_modules),
                   ]
    



_gssapi = Extension(name = "_gssapi",
                    sources = ["gssapi.i"],
                    extra_compile_args = ['-Wall'],
                    libraries = ["gssapi_krb5"],
                    depends = ["gssapi.c"])


setup(name = "gssapi",
      version = "0.0.0", # import this?
      py_modules = ["gssapi"],
      ext_modules = [_gssapi],
      description = "Python wrapping (via SWIG) of the C gssapi library",
      long_description = DESCRIPTION,
      cmdclass={'build': build},
      
      # These will be the same
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",
      url = "http://www.citi.umich.edu/projects/nfsv4/pynfs/",
      license = "GPL"
      
      )






"""
swig -python gssapi.i
gcc -pthread -Wall -fPIC -I/usr/local/include/python2.5 -c gssapi_wrap.c
gcc -pthread -shared gssapi_wrap.o -L/usr/kerberos/lib -lgssapi_krb5 -o
"""









                   
