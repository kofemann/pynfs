from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import lock_owner4
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

def testFile(t, env):
    """RELEASE_LOCKOWNER - basic test

    FLAGS: releaselockowner all
    DEPEND:
    CODE: RLOWN1
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, lockowner=b"lockowner_RLOWN1")
    check(res)
    res = c.unlock_file(1, fh, res.lockid)
    check(res)
    

    # Release lockowner
    owner = lock_owner4(c.clientid, b"lockowner_RLOWN1")
    res = c.compound([op.release_lockowner(owner)])
    check(res)

def testFile2(t, env):
    """RELEASE_LOCKOWNER 2 - same as basic test but remove
    file before release lockowner.

    FLAGS: releaselockowner all
    DEPEND:
    CODE: RLOWN2
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, lockowner=b"lockowner_RLOWN2")
    check(res)
    res = c.unlock_file(1, fh, res.lockid)
    check(res)

    ops = c.use_obj(c.homedir) + [op.remove(t.word())]
    res = c.compound(ops)
    check(res)

    # Release lockowner
    owner = lock_owner4(c.clientid, b"lockowner_RLOWN2")
    res = c.compound([op.release_lockowner(owner)])
    check(res)

def testLocksHeld(t, env):
    """RELEASE_LOCKOWNER - Locks held test

    FLAGS: releaselockowner all
    DEPEND:
    CODE: RLOWN3
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, lockowner=b"lockowner_RLOWN3")
    check(res)
    owner = lock_owner4(c.clientid, b"lockowner_RLOWN3")
    res2 = c.compound([op.release_lockowner(owner)])
    check(res2, NFS4ERR_LOCKS_HELD)
    res = c.unlock_file(1, fh, res.lockid)
    check(res)
    owner = lock_owner4(c.clientid, b"lockowner_RLOWN3")
    res = c.compound([op.release_lockowner(owner)])
    check(res)
