
from distutils.core import setup

DESCRIPTION = """
nfs4
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
        print("expand = %r" % dir)
        cwd = os.getcwd()
        xdrdir = os.path.join(cwd, dir, 'xdrdef')
        print("xdrdir = %r" % xdrdir)
        if os.path.exists(xdrdir):
            try:
                os.chdir(xdrdir)
                xdr_files = glob(os.path.join(xdrdir, "*.x"))
                for f in xdr_files:
                    # Can conditionalize this
                    # XXX need some way to pass options here
                    xdrgen.run(f)
                    try:
                        os.remove("parser.out")
                        os.remove("parsetab.py")
                    except:
                        print("Remove parse* failed")
            finally:
                os.chdir(cwd)

setup(name = "nfs4",
      version = "0.0.0", # import this?
      package_dir = {"nfs4" : ""},
      packages = ["nfs4", "nfs4.server41tests"],
      description = "NFS version 4.1 tools and tests",
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

