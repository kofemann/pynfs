from distutils.core import setup

DESCRIPTION = """
pynfs
======

Add stuff here.
"""

# XXX BUG THIS IS ***BROKEN***
# We want to call setup.py in each of sub dirs and merge results somehow
def setup(*args, **kwargs):
    print "This is currently broken...everything should already be set up.\nJust go into nfs4 and play."

# from distutils.command.build_py import build_py as _build_py
# from distutils.command.sdist import sdist as _sdist

# import os
# from glob import glob
# import xdrgen

# class build_py(_build_py):
#     """Specialized Python source builder that scans for .x files"""
#     def build_packages (self):
#         # A copy from _build_py, with a call to expand_xdr added
#         for package in self.packages:
#             package_dir = self.get_package_dir(package)
#             self.check_package(package, package_dir)
#             self.expand_xdr(package_dir)
#             modules = self.find_package_modules(package, package_dir)
#             for (package_, module, module_file) in modules:
#                 assert package == package_
#                 self.build_module(module, module_file, package)

#     def expand_xdr(self, dir):
#         cwd = os.getcwd()
#         try:
#             if dir:
#                 os.chdir(dir)
#             xdr_files = glob(os.path.join(dir, "*.x"))
#             for f in xdr_files:
#                 # Can conditionalize this
#                 # XXX need some way to pass options here
#                 xdrgen.run(f)
#                 try:
#                     os.remove("parser.out")
#                     os.remove("parsetab.py")
#                 except:
#                     print "Remove parse* failed"
#         finally:
#             os.chdir(cwd)

# class sdist(_sdist):
#     # def get_file_list (self):
#     pass

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

