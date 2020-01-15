from xdrdef.nfs4_const import *
from .environment import check
import os
import nfs_ops
op = nfs_ops.NFS4ops()

def testStale(t, env):
    """SETCLIENTID_CONFIRM with unknown id should return NFS4ERR_STALE_CLIENTID

    FLAGS: setclientidconfirm all
    CODE: CIDCF1
    """
    c = env.c1
    res = c.compound([op.setclientid_confirm(0,b'')])
    check(res, NFS4ERR_STALE_CLIENTID, "SETCLIENTID_CONFIRM with unknown id=0")

def testBadConfirm(t, env):
    """SETCLIENTID_CONFIRM with case not covered in RFC

    FLAGS: ganesha
    CODE: CIDCF2
    """
    c = env.c1
    id = b"Clientid_for_%s_pid=%i" % (t.word(), os.getpid())
    clientid, idconfirm = c.init_connection(id)

    res = c.compound([c.setclientid(id=id)])
    check(res)
    # Now confirm 1st set again, instead of 2nd
    res = c.compound([op.setclientid_confirm(clientid, idconfirm)])
    check(res, msg="SETCLIENTID_CONFIRM with case not covered in RFC, "
          "seems most likely should do nothing and")

def testAllCases(t, env):
    """SETCLIENTID_CONFIRM with each case from RFC

    FLAGS: setclientidconfirm all
    CODE: CIDCF3
    """
    c = env.c1
    id = b"Clientid_for_%s_pid=%i" % (t.word(), os.getpid())
    # no (**c*s), no (**c*s)
    res = c.compound([op.setclientid_confirm(0,b'')])
    check(res, NFS4ERR_STALE_CLIENTID, "SETCLIENTID_CONFIRM with unknown id=0")
    # no (**c*s) and no (*xd*t), (*xc*s)
    c.init_connection(id)
    # no (**c*s) and (*xd*t), (*xc*s)
    clientid, idconfirm = c.init_connection(id, verifier=b'')
    # (vxc*s), no (vxc**)
    res = c.compound([op.setclientid_confirm(clientid, idconfirm)])
    check(res)
    # (vxc*t), (vxc*s)
    c.init_connection(id, verifier=b'')

