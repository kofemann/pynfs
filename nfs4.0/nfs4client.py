#!/usr/bin/env python3

#
# nfs4client.py - NFS4 interactive client in python
#
# Written by Fred Isaman   <iisaman@citi.umich.edu>
# Copyright (C) 2006 University of Michigan, Center for
#                    Information Technology Integration
#

import sys
if sys.hexversion < 0x03020000:
    print("Requires python 3.2 or higher")
    sys.exit(1)
import os
# Allow to be run stright from package root
if  __name__ == "__main__":
    if os.path.isfile(os.path.join(sys.path[0], 'lib', 'testmod.py')):
        sys.path.insert(1, os.path.join(sys.path[0], 'lib'))

import readline
try:
    import readline
except ImportError:
    print("Module readline not available.")
#else:
#    import rlcompleter
#    readline.parse_and_bind("tab: complete")
#import cmd
import nfs4lib
import xdrdef.nfs4_type
import xdrdef.nfs4_const
import xdrdef.nfs4_pack
import code
import traceback

class PyShell(code.InteractiveConsole):
    def __init__(self, server):
        self.client = nfs4lib.NFS4Client("myid", server, homedir = [])
        self.modify_packers()
        locals = {'__builtins__': globals()['__builtins__'],
                  '__name__':'__main__',
                  '__doc__':None}
        code.InteractiveConsole.__init__(self, locals)
        self.myimport(nfs4_type)
        self.myimport(nfs4_const)
        self.importops()
        #self.oldcompleter = readline.get_completer()
        readline.set_completer(self.complete)
        readline.parse_and_bind("tab: complete")

    def myimport(self, mod):
        """Basically do a 'from <mod> import *' """
        for attr in dir(mod):
            if attr[0] != '_':
                self.locals[attr] = getattr(mod, attr)

    def importops(self):
        d = self.locals
        for attr in dir(self.client):
            if attr.endswith("_op"):
                key = attr[:-3].upper()
                d[key] = getattr(self.client, attr)
        d["COMPOUND"] = self.client.compound
        d["NULL"] = self.client.null
        d['fattr4_from_dict'] = nfs4lib.dict2fattr
        d['fattr4_to_dict'] = nfs4lib.fattr2dict
        d['fattr4_names'] = nfs4lib.get_bitnumattr_dict()
        d['bitmap4_from_list'] = nfs4lib.list2bitmap
        d['bitmap4_to_list'] = nfs4lib.bitmap2list

    def complete(self, text, state):
        def mygetattr(inst, attr):
            if inst is None:
                return self.locals[attr]
            else:
                return getattr(inst, attr)
        #print("\nCalled complete(%s, %i)" % (text, state))
        if text.startswith('.'):
            # XXX TODO - handle array indexing
            line = readline.get_line_buffer()
            # print("Line: ", repr(line))
            return None
        vars = text.split('.')
        base = vars[:-1]
        # Look up base variable
        if base:
            try:
                inst = eval('.'.join(base), self.locals)
            except:
                print("\nFAIL")
                traceback.print_exc()
                return None
        else:
            inst = None
        # Get list of base variable attributes
        count = 0
        if inst is None:
            list = self.locals.keys()
        else:
            list = dir(inst)
        # Scan through list, and report possible completions
        for attr in list:
            if attr.startswith(vars[-1]):
                count += 1
                if count > state:
                    if callable(mygetattr(inst, attr)):
                        return '.'.join(base + [attr+'('])
                    else:
                        return '.'.join(base + [attr])
        return None

    def modify_packers(self):
        def new_entry_repr(self):
            out = []
            if self.cookie is not None:
                out += ['cookie=%s' % repr(self.cookie)]
            if self.name is not None:
                out += ['name=%s' % repr(self.name)]
            if self.attrs is not None:
                out += ['attrs=%s' % repr(self.attrs)]
            return 'entry4(%s)' % ', '.join(out)
        nfs4_type.entry4.__repr__ = new_entry_repr

def main(server):
    c = PyShell(server)
    c.interact("Try COMPOUND([PUTROOTFH()])")
    print("Goodbye!")

if __name__ == "__main__":
    main(sys.argv[1])
