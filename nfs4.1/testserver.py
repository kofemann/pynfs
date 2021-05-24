#!/usr/bin/env python3
# nfs4stest.py - nfsv4 server tester
#
# Requires python 3.2
#
# Written by Fred Isaman <iisaman@citi.umich.edu>
# Copyright (C) 2004 University of Michigan, Center for
#                    Information Technology Integration
#
# Based on pynfs
# Written by Peter Astrand <peter@cendio.se>
# Copyright (C) 2001 Cendio Systems AB (http://www.cendio.se)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


import use_local # HACK so don't have to rebuild constantly
import sys
if sys.hexversion < 0x03020000:
    print("Requires python 3.2 or higher")
    sys.exit(1)
import os

import nfs4lib
import testmod
from optparse import OptionParser, OptionGroup, IndentedHelpFormatter
import server41tests.environment as environment
import socket
import rpc.rpc as rpc
import pickle

VERSION="0.2" # How/when update this?

# Auth_sys defaults
HOST = os.fsencode(socket.gethostname())
if not hasattr(os, "getuid"):
    UID = 4321
else:
    UID = os.getuid()
if not hasattr(os, "getgid"):
    GID = 42
else:
    GID = os.getgid()

def scan_options(p):
    """Parse command line options
    """
    p.add_option("--showflags", action="store_true", default=False,
                 help="Print a list of all possible flags and exit")
    p.add_option("--showcodes", action="store_true", default=False,
                 help="Print a list of all test codes and exit")
    p.add_option("--showcodesflags", action="store_true", default=False,
                 help="Print a list of all test codes with their flags and exit")
    p.add_option("--noinit", action="store_true", default=False,
                 help="Skip initial cleanup of test directory")
    p.add_option("--nocleanup", action="store_true", default=False,
                 help="Skip final cleanup of test directory")
    p.add_option("--outfile", "--out", default=None, metavar="FILE",
                 help="Store test results in FILE [%default]")
    p.add_option("--jsonout", "--json", default=None, metavar="FILE",
                 help="Store test results in JSON format [%default]")
    p.add_option("--xmlout", "--xml", default=None, metavar="FILE",
                 help="Store test results in xml format [%default]")
    p.add_option("--debug_fail", action="store_true", default=False,
                 help="Force some checks to fail")
    p.add_option("--minorversion", type="int", default=1,
                 metavar="MINORVERSION", help="Choose NFSv4 minor version")

    g = OptionGroup(p, "Security flavor options",
                    "These options choose or affect the security flavor used.")
    g.add_option("--security", default='sys',
                 help="Choose security flavor such as krb5i [%default]")
    g.add_option("--uid", default=UID, type='int',
                 help="uid for auth_sys [%i]" % UID)
    g.add_option("--gid", default=GID, type='int',
                 help="gid for auth_sys [%i]" % GID)
    g.add_option("--machinename", default=HOST, metavar="HOST",
                 help="Machine name to use for auth_sys [%s]" % HOST)
    p.add_option_group(g)

    g = OptionGroup(p, "Test selection options",
                    "These options affect how flags are interpreted.")
    g.add_option("--force", action="store_true", default=False,
                 help="Force tests to be run, ignoring dependencies.")
    g.add_option("--rundeps", action="store_true", default=False,
                 help="Force test dependencies to be run, "
                 "even if not requested on command line")
    p.add_option_group(g)

    g = OptionGroup(p, "Test output options",
                    "These options affect how test results are shown.")
    g.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Show tests as they are being run")
    g.add_option("--showpass", action="store_true", default=True,
                 help="Show passed tests [default]")
    g.add_option("--hidepass", action="store_false", dest="showpass",
                 help="Hide passed tests")
    g.add_option("--showwarn", action="store_true", default=True,
                 help="Show tests that gave warnings [default]")
    g.add_option("--hidewarn", action="store_false", dest="showwarn",
                 help="Hide tests that gave warnings")
    g.add_option("--showfail", action="store_true", default=True,
                 help="Show failed tests [default]")
    g.add_option("--hidefail", action="store_false", dest="showfail",
                 help="Hide failed tests")
    g.add_option("--showomit", action="store_true", default=False,
                 help="Show omitted tests")
    g.add_option("--hideomit", action="store_false", dest="showomit",
                 help="Hide omitted tests [default]")
    g.add_option("--showtraffic", action="store_true", default=False,
                 help="Show NFS packet information")
    g.add_option("--hidetraffic", action="store_false", dest="showtraffic",
                 help="Hide NFS packet information [default]")
    p.add_option_group(g)

    g = OptionGroup(p, "Test tree options",
                    "If the tester cannot create various objects, certain "
                    "tests will not run.  You can indicate pre-existing "
                    "objects on the server which can be used "
                    "(they will not be altered).")
    g.add_option("--maketree", action="store_true", default=False,
                 help="(Re)create the test tree of object types")
    g.add_option("--uselink", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as symlink")
    g.add_option("--useblock", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as block device")
    g.add_option("--usechar", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as char device")
    g.add_option("--usesocket", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as socket")
    g.add_option("--usefifo", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as fifo")
    g.add_option("--usefile", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as regular file")
    g.add_option("--usedir", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as directory")
    g.add_option("--usespecial", default=None, metavar="OBJPATH",
                 help="Use SERVER:/OBJPATH as directory")
    g.add_option("--userofs", default=None, metavar="DIRPATH",
                 help="Use SERVER:/DIRPATH for ROFS tests")
    g.add_option("--usefh", default=None, metavar="FH",
                 help="Use FH for certain specialized tests")
    p.add_option_group(g)

    g = OptionGroup(p, "Server workaround options",
                    "Certain servers handle certain things in unexpected ways."
                    " These options allow you to alter test behavior so that "
                    "they will run.")
    g.add_option("--secure", action="store_true", default=False,
                 help="Try to use 'secure' port number <1024 for client [False]")
    p.add_option_group(g)


    g = OptionGroup(p, "Server reboot script options",
                    "When running reboot scripts, these options determine "
                    "the scripts and arguments used to control how the "
                    "server is restarted.")

    g.add_option("--serverhelper", default=None, metavar="FILE",
                 help="Use script to perform special actions on server")

    g.add_option("--serverhelperarg", default=None, metavar="ARG",
                 help="Pass ARG as first argument to serverhelper");

    p.add_option_group(g)

    return p.parse_args()

class Argtype(object):
    """Args that are not options are either flags or testcodes"""
    def __init__(self, obj, run=True, flag=True):
        self.isflag = flag  # True if flag, False if a test
        self.run = run      # True for inclusion, False for exclusion
        self.obj = obj      # The flag mask or test itself

    def __str__(self):
        return "Isflag=%i, run=%i" % (self.isflag, self.run)

def run_filter(test, options):
    """Determine whether a test was directly asked for by the command line."""
    run = False   # default
    if not (test.versions[0] <= options.minorversion <= test.versions[1]):
        return run
    for arg in options.args:
        if arg.isflag:
            if test.flags & arg.obj:
                run = arg.run
        else:
            if test == arg.obj:
                run = arg.run
    return run

def printflags(list):
    """Print all legal flag names, which are given in list"""
    from xdrdef.nfs4_const import nfs_opnum4
    command_names = [s.lower()[3:].replace('_', '') \
                     for s in nfs_opnum4.values()]
    list = sorted(list)
    # First print(command names)
    print
    for s in list:
        if s in command_names:
            print(s)
    # Then everything else
    print
    for s in list:
        if s not in command_names:
            print(s)

def main():
    p = OptionParser("%prog SERVER:/PATH [options] flags|testcodes\n"
                     "       %prog --help\n"
                     "       %prog SHOWOPTION",
                     version="%prog "+VERSION,
                     formatter=IndentedHelpFormatter(2, 25)
                     )
    opt, args = scan_options(p)
    environment.nfs4client.SHOW_TRAFFIC = opt.showtraffic

    # Create test database
    tests, fdict, cdict = testmod.createtests('server41tests')

    # Deal with any informational options
    if opt.showflags:
        printflags(fdict.keys())
        sys.exit(0)

    if opt.showcodes:
        codes = sorted(cdict.keys())
        for c in codes:
            print(c)
        sys.exit(0)

    if opt.showcodesflags:
        codes = sorted(cdict.keys())
        for c in codes:
            print(c, "FLAGS:", ', '.join(cdict[c].flags_list))
        sys.exit(0)

    # Grab server info and set defaults
    if not args:
        p.error("Need a server")
    url = args.pop(0)
    server_list, opt.path = nfs4lib.parse_nfs_url(url)

    if not server_list:
        p.error("%s not a valid server name" % url)

    opt.server, opt.port = server_list[0]

    if not args:
        p.error("No tests given")

    # Check --use* options are valid
    for attr in dir(opt):
        if attr.startswith('use') and attr != "usefh":
            path = getattr(opt, attr)
            #print(attr, path)
            if path is None:
                path = opt.path + [b'tree', os.fsencode(attr[3:])]
            else:
                # FIXME - have funct that checks path validity
                if path[0] != b'/':
                    p.error("Need to use absolute path for --%s" % attr)
                # print(path)
                if path[-1] == b'/' and attr != 'usedir':
                    p.error("Can't use dir for --%s" %attr)
                try:
                    path = nfs4lib.path_components(path)
                except Exception as e:
                    p.error(e)
            setattr(opt, attr, [comp for comp in path if comp])

    # Check that --security option is valid
    # FIXME STUB
    tempd = {'none' : (rpc.AUTH_NONE, 0),
             'sys'  : (rpc.AUTH_SYS, 0),
             'krb5' : (rpc.RPCSEC_GSS, 1),
             'krb5i': (rpc.RPCSEC_GSS, 2),
             'krb5p': (rpc.RPCSEC_GSS, 3),
             }
    if opt.security not in tempd:
        p.error("Unknown security: %s\nValid flavors are %s" %
                (opt.security, str(tempd.keys())))

    # flavor has changed from class to int
    opt.flavor, opt.service = tempd[opt.security]

    if opt.flavor not in rpc.security.supported:
        if opt.flavor == rpc.RPCSEC_GSS:
            p.error("RPCSEC_GSS not supported,"
                    " could not find compile gssapi module")
        else:
            p.error("Unsupported security flavor")

    # Make sure args are valid
    opt.args = []
    for a in args:
        if a.lower().startswith('no'):
            include = False
            a = a[2:]
        else:
            include = True
        if a in fdict:
            opt.args.append(Argtype(fdict[a], include))
        elif a in cdict:
            opt.args.append(Argtype(cdict[a], include, flag=False))
        else:
            p.error("Unknown code or flag: %s" % a)

    # DEBUGGING
    environment.debug_fail = opt.debug_fail

    # Place tests in desired order
    tests.sort() # FIXME - add options for random sort

    # Run the tests and save/print(results)
    try:
        env = environment.Environment(opt)
        env.init()
    except socket.gaierror as e:
        if e.args[0] == -2:
            print("Unknown server '%s'" % opt.server)
        print(sys.exc_info()[1])
        sys.exit(1)
    except Exception as e:
        print("Initialization failed, no tests run.")
        if not opt.maketree:
            print("Perhaps you need to use the --maketree option")
        if not opt.secure:
            print("Perhaps you need to use the --secure option or "
                  "configure server to allow connections from high ports")
        raise
        print(sys.exc_info()[1])
        sys.exit(1)
    if opt.outfile is not None:
        fd = open(opt.outfile, 'wb')
    try:
        clean_finish = False
        testmod.runtests(tests, opt, env, run_filter)
        clean_finish = True
    finally:
        if opt.outfile is not None:
            pickle.dump(tests, fd, 0)
        if not clean_finish:
            testmod.printresults(tests, opt)
    try:
        fail = False
        env.finish()
    except Exception as e:
        fail = True
        err = str(e)
    testmod.printresults(tests, opt)
    if fail:
        print("\nWARNING: could not clean testdir due to:\n%s\n" % err)

    if opt.jsonout is not None:
        testmod.json_printresults(tests, opt.jsonout)
    elif opt.xmlout is not None:
        testmod.xml_printresults(tests, opt.xmlout)

if __name__ == "__main__":
    main()
