from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, use_obj
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading


current_stateid = stateid4(1, b'\0' * 12)

def testOpenAndClose(t, env):
    """test current state id processing by having OPEN and CLOSE
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID1
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    open_op = open_create_file_op(sess1, env.testname(t), open_create=OPEN4_CREATE)
    res = sess1.compound(open_op + [op.close(0, current_stateid)])
    check(res, NFS4_OK)

def testLockLockU(t, env):
    """test current state id processing by having LOCK and LOCKU
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID2
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    open_to_lock_owner = open_to_lock_owner4( 0, stateid, 0, lock_owner4(0, b"lock1"))
    lock_owner = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_ops = [ op.lock(WRITE_LT, False, 0, NFS4_UINT64_MAX, lock_owner),
        op.locku(WRITE_LT, 0, current_stateid, 0, NFS4_UINT64_MAX) ]
    res = sess1.compound([op.putfh(fh)] + lock_ops)
    check(res, NFS4_OK)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testOpenWriteClose(t, env):
    """test current state id processing by having OPEN, WRITE and CLOSE
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID3
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    data = b"write test data"
    open_op = open_create_file_op(sess1, env.testname(t), open_create=OPEN4_CREATE)
    res = sess1.compound(open_op + [op.write(current_stateid, 5, FILE_SYNC4, data),
        op.close(0, current_stateid)])
    check(res, NFS4_OK)

def testLockWriteLocku(t, env):
    """test current state id processing by having LOCK, WRITE and LOCKU
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID4
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    data = b"write test data"
    open_to_lock_owner = open_to_lock_owner4( 0, stateid, 0, lock_owner4(0, b"lock1"))
    lock_owner = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_ops = [ op.lock(WRITE_LT, False, 0, NFS4_UINT64_MAX, lock_owner),
        op.write(current_stateid, 5, FILE_SYNC4, data),
        op.locku(WRITE_LT, 0, current_stateid, 0, NFS4_UINT64_MAX),
        op.close(0, stateid)]
    res = sess1.compound([op.putfh(fh)] + lock_ops)
    check(res, NFS4_OK)

def testOpenLookupClose(t, env):
    """test current state id processing by having OPEN, LOOKUP and CLOSE
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID5
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    fname = env.testname(t)
    open_op = open_create_file_op(sess1, fname, open_create=OPEN4_CREATE)

    lookup_op = env.home + [op.lookup(fname)]
    res = sess1.compound(open_op + lookup_op + [op.close(0, current_stateid)])
    check(res, [NFS4ERR_STALE_STATEID, NFS4ERR_BAD_STATEID])

    # An unknown number of lookups will be present
    for r in res.resarray:
        if r.resop == OP_OPEN:
            stateid = r.stateid
        elif r.resop == OP_GETFH:
            fh = r.object
            break

    # Test passed, now cleanup!
    res = sess1.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)

def testCloseNoStateid(t, env):
    """test current state id processing by having CLOSE
       without operation which provides stateid

    FLAGS: currentstateid all
    CODE: CSID6
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = sess1.compound([op.putfh(fh), op.close(0, current_stateid)])
    check(res, [NFS4ERR_STALE_STATEID, NFS4ERR_BAD_STATEID])

    # Test passed, now cleanup!
    res = sess1.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)

def testOpenLayoutGet(t, env):
    """test current state id processing by having OPEN and LAYOUTGET
       in a single compound

    FLAGS: currentstateid pnfs
    CODE: CSID7
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    open_op = open_create_file_op(sess, env.testname(t), open_create=OPEN4_CREATE)
    res = sess.compound( open_op +
           [op.layoutget(False, LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, current_stateid, 0xffff)])
    check(res, NFS4_OK)
    fh = res.resarray[-2].object
    stateid = res.resarray[-3].stateid
    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenSetattr(t, env):
    """test current state id processing by having OPEN and SETATTR
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID8
    """
    size = 8
    sess = env.c1.new_client_session(env.testname(t))

    open_op = open_create_file_op(sess, env.testname(t), open_create=OPEN4_CREATE)
    res = sess.compound( open_op +
           [op.getfh(), op.setattr(current_stateid, {FATTR4_SIZE: size})])
    check(res, NFS4_OK)
    fh = res.resarray[-3].object
    stateid = res.resarray[-4].stateid
    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenFreestateidClose(t, env):
    """test current state id processing by having OPEN, FREE_STATEID and CLOSE
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID9
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    open_op = open_create_file_op(sess1, env.testname(t), open_create=OPEN4_CREATE)
    res = sess1.compound(open_op + [op.free_stateid(current_stateid), op.close(0, current_stateid)])
    check(res, NFS4ERR_LOCKS_HELD)
    fh = res.resarray[-2].object
    stateid = res.resarray[-3].stateid

    # Test passed, now cleanup!
    res = sess1.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)


def testOpenSaveFHLookupRestoreFHClose(t, env):
    """test current state id processing by having OPEN, SAVEFH, LOOKUP, RESTOREFH and CLOSE
       in a single compound

    FLAGS: currentstateid all
    CODE: CSID10
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    fname = env.testname(t)
    open_op = open_create_file_op(sess1, fname, open_create=OPEN4_CREATE)
    lookup_op = env.home
    res = sess1.compound(lookup_op + [op.getfh()])
    check(res)
    fh = res.resarray[-1].object
    res = sess1.compound(open_op + [op.savefh(), op.putfh(fh), op.restorefh(), op.close(0, current_stateid)])
    check(res)
