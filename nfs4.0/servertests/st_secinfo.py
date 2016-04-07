from nfs4_const import *
from environment import check, get_invalid_utf8strings

# XXX Do this for each object type
def testValid(t, env):
    """SECINFO on existing file

    FLAGS: secinfo all
    DEPEND:
    CODE: SEC1
    """
    c = env.c1
    dir = env.opts.usefile[:-1]
    filename = env.opts.usefile[-1]
    ops = c.use_obj(dir)
    ops += [c.secinfo_op(filename)]
    res = c.compound(ops)
    check(res)
    # Make sure at least one security mechanisms is returned.
    if len(res.resarray[-1].switch.switch) == 0:
        t.fail("SECINFO returned empty mechanism list")
    
def testNotDir(t, env):
    """SECINFO with cfh not a directory should return NFS4ERR_NOTDIR

    FLAGS: secinfo all
    DEPEND: SEC1
    CODE: SEC2
    """
    c = env.c1
    ops = c.use_obj(env.opts.usefile)
    ops += [c.secinfo_op('foo')]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "SECINFO with cfh a file")

def testVaporFile(t, env):
    """SECINFO on non-existing object should return NFS4ERR_NOENT

    FLAGS: secinfo all
    DEPEND: SEC1
    CODE: SEC3
    """
    c = env.c1
    newdir = c.homedir + [t.code]
    res = c.create_obj(newdir)
    check(res)
    ops = c.use_obj(newdir)
    ops += [c.secinfo_op('vapor')]
    res = c.compound(ops)
    check(res, NFS4ERR_NOENT, "SECINFO on nonexistant file %s/vapor" % t.code)

def testNoFh(t, env):
    """SECINFO should fail with NFS4ERR_NOFILEHANDLE if no cfh

    FLAGS: secinfo all
    DEPEND: SEC1
    CODE: SEC4
    """
    c = env.c1
    ops = [c.secinfo_op('vapor')]
    res = c.compound(ops)
    check(res, NFS4ERR_NOFILEHANDLE, "SECINFO with no <cfh>")

def testZeroLenName(t, env):
    """SECINFO with zero length name should return NFS4ERR_INVAL

    FLAGS: secinfo all
    DEPEND: SEC1
    CODE: SEC5
    """
    c = env.c1
    newdir = c.homedir + [t.code]
    res = c.create_obj(newdir)
    check(res)
    ops = c.use_obj(newdir)
    ops += [c.secinfo_op('')]
    res = c.compound(ops)
    check(res, NFS4ERR_INVAL, "SECINFO with zero-length name")

def testInvalidUtf8(t, env):
    """SECINFO with bad UTF-8 name strings should return NFS4ERR_INVAL

    FLAGS: secinfo utf8 ganesha
    DEPEND: SEC1
    CODE: SEC6
    """
    c = env.c1
    newdir = c.homedir + [t.code]
    res = c.create_obj(newdir)
    check(res)
    baseops = c.use_obj(newdir)
    for name in get_invalid_utf8strings():
        res = c.compound(baseops + [c.secinfo_op(name)])
        check(res, NFS4ERR_INVAL, "SECINFO of non-existant file with invalid "
                                  "utf8 name %s" % repr(name))
        
    
def testRPCSEC_GSS(t, env):
    """SECINFO must return at least RPCSEC_GSS

    per section 3.2.1.1 of RFC

    FLAGS: secinfo all
    DEPEND: SEC1
    CODE: SEC7
    """
    c = env.c1
    dir = env.opts.usefile[:-1]
    filename = env.opts.usefile[-1]
    ops = c.use_obj(dir)
    ops += [c.secinfo_op(filename)]
    res = c.compound(ops)
    check(res)
    # Make sure at least one security mechanisms is RPCSEC_GSS
    # XXX Check contents of triples more carefully
    mech_list = res.resarray[-1].switch.switch
    for triple in mech_list:
        if triple.flavor == 6: # RPCSEC_GSS
            return
    t.fail("SECINFO returned mechanism list without RPCSEC_GSS")
    
