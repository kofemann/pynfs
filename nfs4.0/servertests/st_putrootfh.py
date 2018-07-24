from xdrdef.nfs4_const import *
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

def testSupported(t, env):
    """Do a simple PUTROOTFH

    FLAGS: putrootfh all
    CODE: ROOT1
    """
    c = env.c1
    ops = [op.putrootfh()]
    res = c.compound(ops)
    check(res)
