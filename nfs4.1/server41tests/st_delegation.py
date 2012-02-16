from st_create_session import create_session
from st_open import open_claim4
from nfs4_const import *

from environment import check, checklist, fail, create_file, open_file, close_file
from nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
import nfs4_ops as op
import threading

def testReadDeleg(t, env):
    """Test read delgation handout and return

    FLAGS: open deleg all
    CODE: DELEG1
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    # c1 - OPEN - READ
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    c1.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c1.cb_post_hook(OP_CB_RECALL, post_hook)
    sess1 = c1.create_session()
    sess1.compound([op.reclaim_complete(FALSE)])
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE or deleg.delegation_type == OPEN_DELEGATE_NONE_EXT:
        fail("Could not get delegation")
    # c2 - OPEN - WRITE
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
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

def testWriteDeleg(t, env):
    """Test write delgation handout and return

    FLAGS: open deleg all
    CODE: DELEG2
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    # c1 - OPEN - WRITE
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    c1.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c1.cb_post_hook(OP_CB_RECALL, post_hook)
    sess1 = c1.create_session()
    sess1.compound([op.reclaim_complete(FALSE)])
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_BOTH |
                      OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE or deleg.delegation_type == OPEN_DELEGATE_NONE_EXT:
        fail("Could not get delegation")
    # c2 - OPEN - READ
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
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

def testAnyDeleg(t, env):
    """Test any delgation handout and return

    FLAGS: open deleg all
    CODE: DELEG3
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    # c1 - OPEN - READ
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    c1.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c1.cb_post_hook(OP_CB_RECALL, post_hook)
    sess1 = c1.create_session()
    sess1.compound([op.reclaim_complete(FALSE)])
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_ANY_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE or deleg.delegation_type == OPEN_DELEGATE_NONE_EXT:
        fail("Could not get delegation")
    # c2 - OPEN - WRITE
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
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
