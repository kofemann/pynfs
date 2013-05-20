from nfs4_const import *
from nfs4_type import *
from environment import check, checklist, fail, create_file, open_file, create_confirm
import sys
import os
import nfs4lib
import nfs4_ops as op
from rpc import RPCTimeout

# NOTE - reboot tests are NOT part of the standard test suite

def _getleasetime(sess):
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_LEASE_TIME)])
    return res.resarray[-1].obj_attributes[FATTR4_LEASE_TIME]

def _waitForReboot(c, sess, env):
    env.serverhelper("reboot")
    # Wait until the server is back up.
    # The following blocks until it gets a response,
    # which happens when the server comes back up.
    env.c1.c1 = env.c1.connect(env.c1.server_address)

def create_session(c, cred=None, flags=0):
    """Send a simple CREATE_SESSION"""
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    res = c.c.compound([op.create_session(c.clientid, c.seqid, flags,
                                        chan_attrs, chan_attrs,
                                        123, sec)], cred)
    return res

def reclaim_complete(sess):
    rc_op = op.reclaim_complete(rca_one_fs=False)
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
    _waitForReboot(c, sess, env)
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
