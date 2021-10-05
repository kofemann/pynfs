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


def _getleasetime(sess):
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_LEASE_TIME)])
    return res.resarray[-1].obj_attributes[FATTR4_LEASE_TIME]

def cour_lockargs(fh, stateid):
    open_to_lock_owner = open_to_lock_owner4( 0, stateid, 0, lock_owner4(0, b"lock1"))
    lock_owner = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_ops = [ op.lock(WRITE_LT, False, 0, NFS4_UINT64_MAX, lock_owner) ]
    return [op.putfh(fh)] + lock_ops

def testLockSleepLockU(t, env):
    """test server courtesy by having LOCK and LOCKU
       in separate compounds, separated by a sleep of twice the lease period

    FLAGS: courteous
    CODE: COUR1
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t))
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = sess1.compound(cour_lockargs(fh, stateid))
    check(res, NFS4_OK)

    lease_time = _getleasetime(sess1)
    env.sleep(lease_time * 2, "twice the lease period")

    lock_stateid = res.resarray[-1].lock_stateid
    lock_ops = [ op.locku(WRITE_LT, 0, lock_stateid, 0, NFS4_UINT64_MAX) ]
    res = sess1.compound([op.putfh(fh)] + lock_ops)
    check(res, NFS4_OK, warnlist = [NFS4ERR_BADSESSION])

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testLockSleepLock(t, env):
    """ensure that a courteous server will allow a conflicting lock from
       a second client, after lease expiry of the first client.
       A discourteous server should allow this too, of course.

    FLAGS: courteous all
    CODE: COUR2
    """

    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t))
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = sess1.compound(cour_lockargs(fh, stateid))
    check(res, NFS4_OK)

    lease_time = _getleasetime(sess1)
    env.sleep(lease_time + 10, "the lease period + 10 secs")

    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    res = open_file(sess2, env.testname(t), access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = sess2.compound(cour_lockargs(fh, stateid))
    check(res, NFS4_OK)
