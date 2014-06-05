"""For each OP_<NAME> in nfs_argop4 and nfs_cb_argop4, create a function
<name>() that returns the appropriate *_argop4 structure, hiding
this routine packing from the user.
"""

from xdrdef import nfs4_type
from xdrdef import nfs4_const

from xdrdef import nfs3_type
from xdrdef import nfs3_const

def nfs4_op_names():
    skip = len('OP_')
    ops = [ x.lower()[skip:] for x in nfs4_const.nfs_opnum4.values() ]
    ops.extend([ x.lower()[skip:] for x in nfs4_const.nfs_cb_opnum4.values()])
    return ops

def nfs3_proc_names():
    pre = 'NFSPROC3_'
    skip = len(pre)
    procs = [ x.lower()[skip:] for x in dir(nfs3_const) if x.startswith(pre) ]
    return procs

class NFSops:
    def __init__(self, is_v4):
        self._is_v4 = is_v4
        if is_v4:
            self._op_names = nfs4_op_names()
            self._type = nfs4_type
            self._const = nfs4_const
            self._args_suffix = '4args'
            self._op_prefix = 'OP_'
        else:
            self._op_names = nfs3_proc_names()
            self._type = nfs3_type
            self._const = nfs3_const
            self._args_suffix = '3args'
            self._op_prefix = 'NFSPROC3_'

    def __getattr__(self, attrname):
        if attrname in self._op_names:
            return lambda *args: self._handle_op(attrname, args)

    def _handle_op(self, opname, args):
        enum_name = opname.upper()

        # RPC "args" class to create
        class_name = "%s%s" % (enum_name, self._args_suffix)
        klass = getattr(self._type, class_name, None)

        if self._is_v4:
            # stuff class into argop

            # args to pass to argop __init__
            opnum = getattr(self._const, self._op_prefix + enum_name)
            kwargs = {}

            if klass:
                # otherwise it takes no arguments
                if type(klass) is dict:
                    assert len(args) == 1
                    arg = args[0]
                else:
                    arg = klass(*args)

                if enum_name.startswith("CB_"):
                    kwargs['opcb%s' % enum_name.lower()] = arg
                else:
                    kwargs['op%s' % enum_name.lower()] = arg

            if enum_name.startswith("CB_"):
                argop = self._type.nfs_cb_argop4
            else:
                argop = self._type.nfs_argop4

            return argop(opnum, **kwargs)

        else:
            # for v3 just return an instance
            return klass(*args)

class NFS3ops(NFSops):
    def __init__(self):
        NFSops.__init__(self, False)

class NFS4ops(NFSops):
    def __init__(self):
        NFSops.__init__(self, True)

