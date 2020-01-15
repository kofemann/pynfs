from xdrdef.nfs4_const import *
from .environment import check
from xdrdef.nfs4_type import nfsace4
from nfs4lib import list2bitmap

# assuming server will accept any small positive integer as an owner
# name.  In particular, these tests probably won't work over krb5,
# when string names are expected.

def testACLsupport(t, env):
    """SETATTR/GETATTR of a simple ACL

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL0
    """
    c = env.c1
    c.init_connection()

    supported = c.supportedAttrs(env.opts.usefile)
    if not (supported & list2bitmap([FATTR4_ACL])):
        t.fail_support("FATTR4_ACL not supported")

def testACL(t, env):
    """SETATTR/GETATTR of a simple ACL

    FLAGS: acl all
    DEPEND: LOOKFILE ACL0
    CODE: ACL5
    """
    c = env.c1
    c.init_connection()

    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    acl = [nfsace4(0, 0, 0, b"123")]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(fh)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)

def testLargeACL(t, env):
    """SETATTR/GETATTR of a large ACL

    FLAGS: acl all
    DEPEND: LOOKFILE ACL0
    CODE: ACL10
    """
    c = env.c1
    c.init_connection()

    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    acl = []
    # using larger id's just to try for a larger reply:
    for i in range(20):
        acl += [nfsace4(0, 0, 0, b"%d" % (i + 10000))]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(fh)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)
