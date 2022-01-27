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
import logging
import datetime

log = logging.getLogger("test.env")

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

def testShareReservation00(t, env):
    """Test OPEN file with OPEN4_SHARE_DENY_WRITE
       1st client opens file with OPEN4_SHARE_DENY_WRITE
       1st client opens same file with OPEN4_SHARE_ACCESS_BOTH and OPEN4_SHARE_DENY_NONE
           expected reply is NFS4ERR_SHARE_DENIED
       2nd client opens file with OPEN4_SHARE_ACCESS_WRITE
           expected reply is NFS4ERR_SHARE_DENIED
       sleep to force lease of client 1 to expire
       3rd client opens file with OPEN4_SHARE_ACCESS_WRITE
           expected reply is NFS4_OK

    FLAGS: courteous all
    CODE: COUR3
    """

    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False, deny=OPEN4_SHARE_DENY_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    claim = open_claim4(CLAIM_FH)
    how = openflag4(OPEN4_NOCREATE)
    oowner = open_owner4(0, b"My Open Owner 2")
    access = OPEN4_SHARE_ACCESS_BOTH|OPEN4_SHARE_ACCESS_WANT_NO_DELEG
    open_op = op.open(0, access, OPEN4_SHARE_DENY_NONE,
                      oowner, how, claim)
    res = sess1.compound([op.putfh(fh), open_op])
    check(res, NFS4ERR_SHARE_DENIED)
    log.info("local open conflict detected - PASSED\n")

    """ 2nd client """
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess1.c.homedir + [name]
    res = open_file(sess2, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res, NFS4ERR_SHARE_DENIED)
    log.info("2nd client open conflict detected - PASSED\n")

    """ force lease of both c1 to expire """
    log.info("force lease to expire...\n")
    lease_time = _getleasetime(sess1)
    env.sleep(lease_time + 10, "the lease period + 10 secs")

    """ 3rd client """
    sess3 = env.c1.new_client_session(b"%s_3" % env.testname(t))

    """ should succeed """
    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess3.c.homedir + [name]
    res = open_file(sess3, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    log.info("3nd client opened OK - no conflict detected - PASSED\n")

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = close_file(sess3, fh, stateid=stateid)
    check(res)

def testShareReservationDB01(t, env):
    """ Test 2 clients with same deny mode
    Client 1 opens file with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ
    Client 2 opens file with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ
    Client 2 open should succeed

    FLAGS: courteous all
    CODE: COUR4
    """

    """ client1 creates file with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ """

    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False,
		access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    """ create 2nd client """
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    """ client2 open file with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ """
    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess2.c.homedir + [name]
    res = open_file(sess2, owner, path, deny=OPEN4_SHARE_DENY_READ,
		access=OPEN4_SHARE_ACCESS_WRITE|OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    log.info("2nd client open OK - PASSED\n")

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

    res = close_file(sess2, fh2, stateid=stateid2)
    check(res)

def testShareReservationDB02(t, env):
    """ Test courtesy clients' file access mode conflicts with deny mode
        client 1 creates file with OPEN4_SHARE_ACCESS_WRITE
        sleep to force lease of client 1 to expire
        client 2 opens file with OPEN4_SHARE_ACCESS_READ & OPEN4_SHARE_DENY_WRITE
            expected reply is NFS4_OK

    FLAGS: courteous all
    CODE: COUR5
    """

    """ client1 creates file with OPEN4_SHARE_ACCESS_WRITE """

    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False,
		access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    log.info("client 1 creates file OK\n")

    """ force lease of client1 to expire """
    log.info("force lease to expire...\n")
    lease_time = _getleasetime(sess1)
    env.sleep(lease_time + 10, "the lease period + 10 secs")

    """ create 2nd client """
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    """ 2nd client open file with OPEN4_SHARE_ACCESS_READ & OPEN4_SHARE_DENY_WRITE """
    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess2.c.homedir + [name]
    res = open_file(sess2, owner, path,
		access=OPEN4_SHARE_ACCESS_READ|OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
		deny=OPEN4_SHARE_DENY_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    log.info("2nd client open OK - PASSED\n")

    res = close_file(sess2, fh, stateid=stateid)
    check(res)

def testShareReservationDB03(t, env):
    """ Test courtesy clients' deny mode conflicts with file access mode
    Client 1 opens file with with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ
    Client 2 opens same file with with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ
        expected reply is NFS4_OK
    sleep to force lease of client 1 and client 2 to expire
    client 3 opens same file with OPEN4_SHARE_ACCESS_READ
        expected reply is NFS4_OK

    FLAGS: courteous all
    CODE: COUR6
    """

    """ client1 creates file with OPEN4_SHARE_ACCESS_WRITE &  OPEN4_SHARE_DENY_READ """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False,
		access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
    check(res)
    log.info("client 1 creates file OK\n")

    """ create 2nd client """
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess2.c.homedir + [name]

    res = open_file(sess2, owner, path,
		access=OPEN4_SHARE_ACCESS_WRITE|OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
		deny=OPEN4_SHARE_DENY_READ)
    check(res)
    log.info("client 2 open file OK\n")

    """ force lease of client1 and client2 to expire """
    log.info("force lease to expire...\n")
    lease_time = _getleasetime(sess1)
    env.sleep(lease_time + 10, "the lease period + 10 secs")

    """ create 3nd client """
    sess3 = env.c1.new_client_session(b"%s_3" % env.testname(t))

    """ client3 open file with OPEN4_SHARE_ACCESS_READ """
    name = env.testname(t)
    owner = b"owner_%s" % name
    path = sess3.c.homedir + [name]
    res = open_file(sess3, owner, path,
		access=OPEN4_SHARE_ACCESS_READ|OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    log.info("3rd client open OK - PASSED\n")

    res = close_file(sess3, fh, stateid=stateid)
    check(res)

def testExpiringManyClients(t, env):
    """ Open a file from lots of clients, wait for those clients to
    expire, then attempt a conflicting open and see how long it takes
    the server to purge the courtesy clients.

    FLAGS: courteous
    CODE: COUR7
    """

    log.info("%s: opening\n" % str(datetime.datetime.now()))
    for i in range(1000):
        s = env.c1.new_client_session(b"%s_Client_%i" % (env.testname(t), i))
        res = create_file(s, env.testname(t), want_deleg=False,
                                    mode=UNCHECKED4,
                                    access=OPEN4_SHARE_ACCESS_WRITE)
        check(res)

    log.info("%s: waiting for lease\n", str(datetime.datetime.now()))
    lease_time = _getleasetime(s)
    env.sleep(lease_time + 10, "the lease period + 10 secs")

    s = env.c1.new_client_session(b"%s_Breaker" % env.testname(t))

    name = env.testname(t)
    owner = b"owner_%s" % name
    path = s.c.homedir + [name]
    log.info("%s: conflicting open\n", str(datetime.datetime.now()))
    res = open_file(s, owner, path,
		access=OPEN4_SHARE_ACCESS_READ|OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
		deny=OPEN4_SHARE_DENY_WRITE)
    log.info("%s: conflicting open done\n", str(datetime.datetime.now()))
    check(res)
