from xdrdef.nfs4_const import *
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

def testSupported(t, env):
    """Do a simple PUTPUBFH

    FLAGS: putpubfh all
    CODE: PUB1
    """

    c = env.c1
    ops = [op.putpubfh()]
    res = c.compound(ops)
    check(res)

def testSameAsRoot(t, env):
    """PUTPUBFH should return same as PUTROOTFH

    Per RFC 2530:
    The public filehandle and the root filehandle (represented by the
    PUTROOTFH operation) should be equivalent

    FLAGS: putpubfh all
    DEPEND: PUB1
    CODE: PUB2
    """

    c = env.c1
    ops = [op.putpubfh(), op.getfh()]
    res = c.compound(ops)
    check(res)
    pubfh = res.resarray[-1].switch.switch.object

    ops = [op.putrootfh(), op.getfh()]
    res = c.compound(ops)
    check(res)
    rootfh = res.resarray[-1].switch.switch.object

    if rootfh != pubfh:
        # This is not a failure, since is merely a "should", but will warn about
        t.pass_warn('Spec says rootfh "should" equal pubfh')
