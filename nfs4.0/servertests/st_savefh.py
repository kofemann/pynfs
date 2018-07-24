from xdrdef.nfs4_const import *
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

# NOTE other tests in restorefh.py
def testNoFh(t, env):
    """SAVEFH should fail with NFS4ERR_NOFILEHANDLE if no (cfh)

    FLAGS: savefh emptyfh all
    CODE: SVFH1
    """
    c = env.c1
    res = c.compound([op.savefh()])
    check(res, NFS4ERR_NOFILEHANDLE, "SAVEFH with no <cfh>")

