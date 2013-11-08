from nfs4_const import *
from environment import check, checklist
from nfs4_type import nfsace4

# assuming server will accept any small positive integer as an owner name:

def testACL(t, env):
    """SETATTR/GETATTR of a simple ACL

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL5
    """
    c = env.c1
    ops = c.use_obj(env.opts.usefile)
    acl = [nfsace4(0, 0, 0,"123")]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(env.opts.usefile)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)

def testLargeACL(t, env):
    """SETATTR/GETATTR of a large ACL

    FLAGS: acl all
    DEPEND: LOOKFILE
    CODE: ACL10
    """
    c = env.c1
    ops = c.use_obj(env.opts.usefile)
    acl = []
    # using larger id's just to try for a larger reply:
    for i in range(200):
        acl += [nfsace4(0, 0, 0, "%d" % (i + 10000))]
    ops += [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res)
    ops = c.use_obj(env.opts.usefile)
    ops += [c.getattr([FATTR4_ACL])]
    res = c.compound(ops)
    check(res)
