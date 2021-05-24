#!/usr/bin/env python3

from distutils.core import setup

DESCRIPTION = """
xdrgen
======

Add stuff here.
"""


setup(name = "xdrgen",
      version = "0.0.0", # import this?
      py_modules = ["xdrgen"],
      scripts = ["xdrgen.py"], # FIXME - make small script that calls module
      description = "Generate python code from .x files",
      long_description = DESCRIPTION,
      #requires = "ply (>=2.0)",

      # These will be the same
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",
      url = "http://www.citi.umich.edu/projects/nfsv4/pynfs/",
      license = "GPL"
      )

