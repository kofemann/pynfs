from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail, open_file, create_file, create_confirm
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib

def testSupported(t, env):
    """Do a simple RECLAIM_COMPLETE

    FLAGS: reclaim_complete all
    CODE: RECC1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    res = sess.compound([op.putrootfh(), op.reclaim_complete(TRUE)])
    check(res)

    res = sess.compound([op.reclaim_complete(FALSE)])
    check(res)

def testReclaimAfterRECC(t, env):
    """If client does subsequent reclaims of locking state after
       RECLAIM_COMPLETE is done, server will return NFS4ERR_NO_GRACE.
       rfc5661 18.51.3

    FLAGS: reclaim_complete all
    CODE: RECC2
    """
    name = env.testname(t)
    c = env.c1.new_client(name)
    sess = c.create_session()

    res = sess.compound([op.reclaim_complete(FALSE)])
    check(res)

    owner = b"owner_%s" % name
    path = sess.c.homedir + [name]
    fh, stateid = create_confirm(sess, owner)

    # Try to reclaims a file which is noexist after RECLAIM_COMPLETE
    res = open_file(sess, owner, path=fh, claim_type=CLAIM_PREVIOUS,
                    access=OPEN4_SHARE_ACCESS_BOTH,
                    deny=OPEN4_SHARE_DENY_NONE,
                    deleg_type=OPEN_DELEGATE_NONE)

    check(res, NFS4ERR_NO_GRACE, warnlist = [NFS4ERR_EXIST | NFS4ERR_RECLAIM_BAD])

    # Cleanup
    res = sess.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)

def testOpenBeforeRECC(t, env):
    """After a client establishes a new client ID, if non-reclaim
       locking operations are done before the RECLAIM_COMPLETE,
       error NFS4ERR_GRACE will be returned. rfc5661 18.51.3

    FLAGS: reclaim_complete all
    CODE: RECC3
    """
    name = env.testname(t)
    c = env.c1.new_client(name)
    sess = c.create_session()

    fname = b"owner_%s" % name
    path = sess.c.homedir + [name]

    res = create_file(sess, fname, path, access=OPEN4_SHARE_ACCESS_BOTH)
    check(res, NFS4ERR_GRACE)

def testDoubleRECC(t, env):
    """If RECLAIM_COMPLETE is done a second time, error
       NFS4ERR_COMPLETE_ALREADY will be returned. rfc5661 18.51.4

    FLAGS: reclaim_complete all
    CODE: RECC4
    """
    name = env.testname(t)
    c = env.c1.new_client(name)
    sess = c.create_session()

    res = sess.compound([op.reclaim_complete(FALSE)])
    check(res)

    # RECLAIM_COMPLETE again
    res = sess.compound([op.reclaim_complete(FALSE)])
    check(res, NFS4ERR_COMPLETE_ALREADY)
