"""For each OP_<NAME> in nfs_argop4 and nfs_cb_argop4, create a function
<name>() that returns the appropriate *_argop4 structure, hiding
this routine packing from the user.
"""
import nfs4_type as _type
import nfs4_const as _const

# This string is our general function template
code = """\
def %(funct_name)s(%(funct_args)s):
    %(create_args)s
    return _type.%(argop)s(_const.OP_%(enum_name)s, %(set_args)s)
"""

def _mappings():
    return _pull_argops(_const.nfs_opnum4) + _pull_argops(_const.nfs_cb_opnum4)

def _pull_argops(op_dict):
    """ For each entry in op_dict, create an appropriate dictionary that can
        be used to fill the 'code' template.
    """
    import inspect
    out = []
    keys = op_dict.keys()
    keys.sort() # Not necessary, but makes scanning the printout easier
    for k in keys:
        # Create a dictionary that will be used to fill the 'code' template
        d = {}
        d["enum_name"] = enum_name = op_dict[k][3:] # <NAME>
        d["funct_name"] = "%s" % enum_name.lower() # <name>
        class_name = "%s4args" % enum_name
        klass = getattr(_type, class_name, None)
        if klass is None:
            # This operation takes no arguments
            d["funct_args"] = d["create_args"] = d["set_args"] = ""
        else:
            if type(klass) is dict:
                arg_list = "enum_value"
                d["create_args"] = "args = enum_value"
            else:
                arg_list = ", ".join(inspect.getargspec(klass.__init__)[0][1:])
                d["create_args"] = "args = _type.%s(%s)" % (class_name, arg_list)
            d["funct_args"] = arg_list
            if enum_name.startswith("CB_"):
                d["set_args"] = "opcb%s=args" % enum_name.lower()[3:]
            else:
                d["set_args"] = "op%s=args" % enum_name.lower()
        if enum_name.startswith("CB_"):
            d["argop"] = "nfs_cb_argop4"
        else:
            d["argop"] = "nfs_argop4"
        out.append(d)
    return out

if __name__ == "__main__":
    for _d in _mappings():
        print code % _d
else:
    for _d in _mappings():
        exec code % _d
    
