#!/usr/bin/env python3

from setuptools import setup

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
      maintainer = "Calum Mackay",
      maintainer_email = "calum.mackay@oracle.com",
      url = "https://linux-nfs.org/wiki/index.php/Pynfs",
      license = "GPL"
      )

