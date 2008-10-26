# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _gssapi

def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name) or (name == "thisown"):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types



ptr2str = _gssapi.ptr2str
GSS_S_COMPLETE = _gssapi.GSS_S_COMPLETE
GSS_S_CONTINUE_NEEDED = _gssapi.GSS_S_CONTINUE_NEEDED
DELEG_FLAG = _gssapi.DELEG_FLAG
MUTUAL_FLAG = _gssapi.MUTUAL_FLAG
REPLAY_FLAG = _gssapi.REPLAY_FLAG
SEQUENCE_FLAG = _gssapi.SEQUENCE_FLAG
CONF_FLAG = _gssapi.CONF_FLAG
INTEG_FLAG = _gssapi.INTEG_FLAG
ANON_FLAG = _gssapi.ANON_FLAG
PROT_READY_FLAG = _gssapi.PROT_READY_FLAG
TRANS_FLAG = _gssapi.TRANS_FLAG

def importName(*args):
    """importName(string name, gss_OID name_type=HOSTBASED_SERVICE) -> name"""
    return _gssapi.importName(*args)

def initSecContext(*args):
    """initSecContext(gss_name_t name, gss_ctx_id_t *context=None, string token=None, gss_cred_id_t cred=None, gss_OID mech=krb5oid, int flags=0, int time=0, gss_channel_bindings_t chan=None) -> context, mech, token, flags, time"""
    return _gssapi.initSecContext(*args)

def acceptSecContext(*args):
    """initSecContext(gss_name_t name, gss_ctx_id_t *context=None, string token=None, gss_cred_id_t cred=None, gss_OID mech=krb5oid, int flags=0, int time=0, gss_channel_bindings_t chan=None) -> context, mech, token, flags, time"""
    return _gssapi.acceptSecContext(*args)

def getMIC(*args):
    """getMIC(gss_ctx_id_t context, string msg, int qop) -> string checksum"""
    return _gssapi.getMIC(*args)

def verifyMIC(*args):
    """verifyMIC(gss_ctx_id_t context, string msg, string checksum) -> qop"""
    return _gssapi.verifyMIC(*args)

def wrap(*args):
    """verifyMIC(gss_ctx_id_t context, string msg, string checksum) -> qop"""
    return _gssapi.wrap(*args)

def unwrap(*args):
    """verifyMIC(gss_ctx_id_t context, string msg, string checksum) -> qop"""
    return _gssapi.unwrap(*args)
cvar = _gssapi.cvar
HOSTBASED_SERVICE = cvar.HOSTBASED_SERVICE
krb5oid = cvar.krb5oid

