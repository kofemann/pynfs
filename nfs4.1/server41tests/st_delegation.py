from st_create_session import create_session
from st_open import open_claim4
from nfs4_const import *

from environment import check, checklist, fail, create_file, open_file, close_file
from nfs4_type import *
import nfs4_ops as op
import nfs4lib
import threading

def _testDeleg(t, env, openaccess, want, breakaccess):
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    sess1 = env.c1.new_client_session("%s_1" % env.testname(t))
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    res = create_file(sess1, env.testname(t), access = openaccess | want)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if    (deleg.delegation_type == OPEN_DELEGATE_NONE or
           deleg.delegation_type == OPEN_DELEGATE_NONE_EXT):
        fail("Could not get delegation")
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, breakaccess, OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    # Wait for recall, and return delegation
    recall.wait() # STUB - deal with timeout
    # Getting here means CB_RECALL reply is in the send queue.
    # Give it a moment to actually be sent
    env.sleep(1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(recall.stateid)])
    check(res)
    # Now get OPEN reply
    res = sess2.listen(slot)
    checklist(res, [NFS4_OK, NFS4ERR_DELAY])

def testReadDeleg(t, env):
    """Test read delegation handout and return

    FLAGS: open deleg all
    CODE: DELEG1
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH)

def testWriteDeleg(t, env):
    """Test write delegation handout and return

    FLAGS: open deleg all
    CODE: DELEG2
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_WRITE,
       OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, OPEN4_SHARE_ACCESS_READ)

def testAnyDeleg(t, env):
    """Test any delegation handout and return

    FLAGS: open deleg all
    CODE: DELEG3
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, OPEN4_SHARE_ACCESS_BOTH);

def testNoDeleg(t, env):
    """Test no delegation handout

    FLAGS: open deleg all
    CODE: DELEG4
    """
    sess1 = env.c1.new_client_session("%s_1" % env.testname(t))
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE:
        fail("Got no delegation, expected OPEN_DELEGATE_NONE_EXT")
    if deleg.delegation_type != OPEN_DELEGATE_NONE_EXT:
        fail("Got a delegation (type "+str(deleg.delegation_type)+") despite asking for none")
    if deleg.ond_why != WND4_NOT_WANTED:
        fail("Wrong reason ("+str(deleg.ond_why)+") for giving no delegation")


def testCBSecParms(t, env):
    """Test auth_sys callbacks

    FLAGS: create_session open deleg all
    CODE: DELEG5
    """
    uid = 17
    gid = 19
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    sys_cred = cbsp_sys_cred = authsys_parms(13, "fake name", uid, gid, [])
    sess1 = c1.create_session(sec = [callback_sec_parms4(AUTH_SYS, sys_cred)])
    sess1.compound([op.reclaim_complete(FALSE)])

    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid
        recall.cred = env.cred.raw_cred.body
        env.notify = recall.set
    def post_hook(arg, env, res):
        return res

    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    res = create_file(sess1, env.testname(t), access = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if    (deleg.delegation_type == OPEN_DELEGATE_NONE or
           deleg.delegation_type == OPEN_DELEGATE_NONE_EXT):
        fail("Could not get delegation")
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    # Wait for recall, and return delegation
    recall.wait() # STUB - deal with timeout
    # Getting here means CB_RECALL reply is in the send queue.
    # Give it a moment to actually be sent
    if recall.cred.uid != uid or recall.cred.gid != gid:
        fail("expected callback with uid, gid == %d, %d, got %d, %d"
                % (uid, gid, recall.cred.uid, recall.cred.gid))
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(recall.stateid)])
    check(res)
    # Now get OPEN reply
    res = sess2.listen(slot)
    checklist(res, [NFS4_OK, NFS4ERR_DELAY])
