
from distutils.core import setup

DESCRIPTION = """
rpc
======

Add stuff here.
"""

from distutils.command.build_py import build_py as _build_py
import os
from glob import glob
try:
    import xdrgen
except ImportError:
    import use_local
    import xdrgen

class build_py(_build_py):
    """Specialized Python source builder that scans for .x files"""
    def build_packages (self):
        # A copy from _build_py, with a call to expand_xdr added
        for package in self.packages:
            package_dir = self.get_package_dir(package)
            self.check_package(package, package_dir)
            self.expand_xdr(package_dir)
            modules = self.find_package_modules(package, package_dir)
            for (package_, module, module_file) in modules:
                assert package == package_
                self.build_module(module, module_file, package)

    def expand_xdr(self, dir):
        cwd = os.getcwd()
        try:
            if dir:
                os.chdir(dir)
            xdr_files = glob(os.path.join(dir, "*.x"))
            for f in xdr_files:
                # Can conditionalize this
                # XXX need some way to pass options here
                xdrgen.run(f)
        finally:
            os.chdir(cwd)

setup(name = "rpc",
      version = "0.0.0", # import this?
      package_dir = {"rpc" : ""},
      packages = ["rpc"],
      description = "GSS enabled RPC client and server",
      long_description = DESCRIPTION,
      cmdclass = {"build_py": build_py},

      # These will be the same
      author = "Fred Isaman",
      author_email = "iisaman@citi.umich.edu",
      maintainer = "Fred Isaman",
      maintainer_email = "iisaman@citi.umich.edu",
      url = "http://www.citi.umich.edu/projects/nfsv4/pynfs/",
      license = "GPL"
      )

