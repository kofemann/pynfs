from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from .environment import check, fail, create_file, open_file, create_confirm, close_file
import sys
import os
import time
import logging
import nfs_ops
op = nfs_ops.NFS4ops()
from rpc import RPCTimeout

# NOTE - reboot tests are NOT part of the standard test suite

log = logging.getLogger("test.env")

def _getleasetime(sess):
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_LEASE_TIME)])
    return res.resarray[-1].obj_attributes[FATTR4_LEASE_TIME]

def _waitForReboot(env):
    env.serverhelper("reboot")
    # Wait until the server is back up.
    # The following blocks until it gets a response,
    # which happens when the server comes back up.
    env.c1.c1 = env.c1.connect(env.c1.server_address)
    # Go ahead and whack the cached session and client ids now
    # to avoid errors in Environment.finish().
    env.c1.sessions = {}
    env.c1.clients = {}
    return int(time.time())

def create_session(c, cred=None, flags=0):
    """Send a simple CREATE_SESSION"""
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    res = c.c.compound([op.create_session(c.clientid, c.seqid, flags,
                                        chan_attrs, chan_attrs,
                                        123, sec)], cred)
    return res

def reclaim_complete(sess):
    rc_op = op.reclaim_complete(FALSE)
    res = sess.compound([rc_op])
    check(res, msg="reclaim_complete")

#####################################################

def testRebootValid(t, env):
    """REBOOT with valid CLAIM_PREVIOUS

    FLAGS: reboot
    DEPEND:
    CODE: REBT1
    """
    name = env.testname(t)
    owner = "owner_%s" % name
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    reclaim_complete(sess)
    fh, stateid = create_confirm(sess, owner)
    sleeptime = 5 + _getleasetime(sess)
    _waitForReboot(env)
    try:
        res = create_session(c)
        check(res, NFS4ERR_STALE_CLIENTID, "Reclaim using old clientid")
        c = env.c1.new_client(env.testname(t))
        sess = c.create_session()
        newleasetime = _getleasetime(sess)
        sleeptime = max(sleeptime, 5 + newleasetime)
        res = open_file(sess, owner, path=fh, claim_type=CLAIM_PREVIOUS,
                       access=OPEN4_SHARE_ACCESS_BOTH,
                       deny=OPEN4_SHARE_DENY_NONE,
                       deleg_type=OPEN_DELEGATE_NONE)
        check(res, msg="Reclaim using newly created clientid")
        reclaim_complete(sess)
    finally:
        env.sleep(sleeptime, "Waiting for grace period to end")

class State(object):
    def __init__(self, name, owner, c, sess, fh):
        self.name = name
        self.owner = owner
        self.c = c
        self.sess = sess
        self.fh = fh

def doTestOneClientGrace(t, env, state):
    res = state.sess.compound([])
    check(res, NFS4ERR_BADSESSION, "Bare sequence after reboot")
    res = create_session(state.c)
    check(res, NFS4ERR_STALE_CLIENTID, "Reclaim using old clientid")
    c = env.c1.new_client(state.name)
    state.c = c
    sess = c.create_session()
    state.sess = sess
    lease_time = _getleasetime(sess)
    res = open_file(sess, state.owner, path=state.fh,
                   claim_type=CLAIM_PREVIOUS,
                   access=OPEN4_SHARE_ACCESS_BOTH,
                   deny=OPEN4_SHARE_DENY_NONE,
                   deleg_type=OPEN_DELEGATE_NONE)
    check(res, msg="Reclaim using newly created clientid")
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    reclaim_complete(sess)
    close_file(sess, fh, stateid=stateid)
    res = open_file(sess, state.owner, claim_type=CLAIM_NULL,
                   access=OPEN4_SHARE_ACCESS_BOTH,
                   deny=OPEN4_SHARE_DENY_NONE,
                   deleg_type=OPEN_DELEGATE_NONE)
    check(res, NFS4ERR_GRACE, "New open during grace")
    return lease_time

def doTestOneClientNoGrace(t, env, state):
    res = open_file(state.sess, state.owner, claim_type=CLAIM_NULL,
                   access=OPEN4_SHARE_ACCESS_BOTH,
                   deny=OPEN4_SHARE_DENY_NONE,
                   deleg_type=OPEN_DELEGATE_NONE)
    if (res.status == NFS4ERR_GRACE):
        return res
    check(res, msg="New open after all clients done reclaiming")
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    close_file(state.sess, fh, stateid=stateid)
    return res

# The server may have lifted the grace period early, but it's not obligated.
# Keep looping until all the clients have done a normal open.  If the server
# didn't lift the grace period early we don't want to fail the test, but we
# do want to log a message.
def doTestAllClientsNoGrace(t, env, states):
        all_done = False
        warn_grace = False
        start_time = int(time.time())
        ok_time = 0
        while not all_done:
            all_done = True
            for state in states:
                res = doTestOneClientNoGrace(t, env, state)
                if res.status == NFS4ERR_GRACE:
                    warn_grace = True
                    all_done = False
                elif not ok_time:
                    ok_time = int(time.time())
            if not all_done:
                time.sleep(1)
        if warn_grace:
            lift_time = ok_time - start_time
            log.warn("server took approximately %d seconds to lift grace "
                        "after all clients reclaimed" % lift_time)

def doTestRebootWithNClients(t, env, n=10):
    boot_time = int(time.time())
    lease_time = 90
    states = []
    block = env.c1.new_client_session("%s_block" % env.testname(t))
    for i in range(n):
        name = "%s_client_%i" % (env.testname(t), i)
        owner = "owner_%s" % name
        c = env.c1.new_client(name)
        sess = c.create_session()
        reclaim_complete(sess)
        fh, stateid = create_confirm(sess, owner)
        states.append(State(name, owner, c, sess, fh))
    lease_time = _getleasetime(sess)
    boot_time = _waitForReboot(env)

    try:
        for i in range(n):
            lease_time = doTestOneClientGrace(t, env, states[i])

        # At this point, all clients should have recovered except for 'block'.
        # Recover that one now.
        block = env.c1.new_client_session("%s_block" % env.testname(t))

        # The server may have lifted the grace period early.  Test it.
        doTestAllClientsNoGrace(t, env, states)

    # If the test went normally, then the grace period should have already
    # ended.  If we got some unexpected error, then wait a bit for the server
    # to expire the clients so cleanup can proceed more smoothly.
    except:
        grace_end_time = boot_time + lease_time + 5
        now = int(time.time())
        if now < grace_end_time:
            sleep_time = grace_end_time - now
            env.sleep(sleep_time, "Waiting for grace period to end")
        raise

def testRebootWithManyClients(t, env):
    """Reboot with many clients

    FLAGS: reboot
    CODE: REBT2a
    """
    return doTestRebootWithNClients(t, env)

def testRebootWithManyManyClients(t, env):
    """Reboot with many many clients

    FLAGS: reboot
    CODE: REBT2b
    """
    return doTestRebootWithNClients(t, env, 100)

def testRebootWithManyManyManyClients(t, env):
    """Reboot with many many many clients

    FLAGS: reboot
    CODE: REBT2c
    """
    return doTestRebootWithNClients(t, env, 1000)
