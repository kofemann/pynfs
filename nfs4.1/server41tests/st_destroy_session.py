from st_create_session import create_session
from xdrdef.nfs4_const import *
from environment import check, fail, create_file, open_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading
import rpc

def testDestroy(t, env):
    """
   - create a session
	- create a new tcp connection
	- Send a DESTROY_SESSION over the new tcp connection.  It should
	  fail with nfserr_conn_not_bound_to_session.
	- Send a SEQUENCE over the new tcp connection.
	- Send a DESTROY_SESSION over the new tcp connection.
	- This time it should succeed.

    FLAGS: destroy_session ganesha
    CODE: DSESS9001
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    rogue = env.c1.connect(env.c1.server_address)
    res = c.c.compound([op.destroy_session(sess.sessionid)], pipe=rogue)
    check(res, NFS4ERR_CONN_NOT_BOUND_TO_SESSION)
    env.c1.compound([sess.seq_op()], pipe=rogue)
    res = c.c.compound([op.destroy_session(sess.sessionid)], pipe=rogue)
    check(res)

def testDestroy2(t, env):
    """
	- create client (exchangeid)
	- create session
	- destroy session
	- create a new session for the same client
	- do something that triggers a callback (look at the delegation
	  tests for example)
	- check that we get the callback

    FLAGS: destroy_session ganesha
    CODE: DSESS9002
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        recall.happened = True
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()
    res = c.c.compound([op.destroy_session(sess1.sessionid)])
    sess2 = c.create_session()
    res = create_file(sess2, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE:
        fail("Could not get delegation")
    c2 = env.c1.new_client("%s_2" % env.testname(t))
    sess3 = c2.create_session()
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
    c.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c.cb_post_hook(OP_CB_RECALL, post_hook)
    slot = sess3.compound_async(env.home + [open_op])
    recall.happened = False
    recall.wait(100) # STUB - deal with timeout
    if not recall.happened:
        fail("Did not get callback")

def testDestroy3(t, env):
    """
	- create client (exchangeid)
	- create session
	- trigger callback; check that it arrives, but don't answer it.
	- destroy session
	- create new session
	- check that a new callback is sent over the new session.  Some
	  servers will do this very quickly, some might take longer.

    FLAGS: destroy_session ganesha
    CODE: DSESS9003
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        recall.happened = True
        env.notify = recall.set # This is called after compound sent to queue
    def bad_post_hook(arg, env, res):
	return None;
    def good_post_hook(arg, env, res):
        return res
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    print "OPEN fh =", repr(fh)
    if deleg.delegation_type == OPEN_DELEGATE_NONE:
        fail("Could not get delegation")
    recall.happened = False
    c2 = env.c1.new_client("%s_2" % env.testname(t))
    sess2 = c2.create_session()
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    c.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c.cb_post_hook(OP_CB_RECALL, bad_post_hook)
    recall.wait(1) # STUB - deal with timeout
    if not recall.happened:
        fail("Did not get callback")
    recall.happened = False
    # since we did not reply to callback, robust server should retry when
    # we give it a new backchannel to use:
    res = c.c.compound([op.destroy_session(sess1.sessionid)])
    c.cb_pre_hook(OP_CB_RECALL, pre_hook)
    c.cb_post_hook(OP_CB_RECALL, good_post_hook)
    sess3 = c.create_session()
    recall.wait(100) # STUB - deal with timeout
    if not recall.happened:
        fail("Did not get callback")

def testDestoryNotFinalOps(t, env):
    """ If the COMPOUND request starts with SEQUENCE, DESTROY_SESSION
        MUST be the final operation in the COMPOUND request.
        rfc5661 18.37.3

    FLAGS: destroy_session ganesha
    CODE: DSESS9004
    """
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()

    sid = sess1.sessionid
    res = c.c.compound([op.sequence(sid, 1, 2, 3, False),
                        op.destroy_session(sess1.sessionid),
                        op.putrootfh()])
    check(res, NFS4ERR_NOT_ONLY_OP)

def testDestoryNotSoleOps(t, env):
    """ If the COMPOUND request does not start with SEQUENCE,
        and DESTROY_SESSION is not the sole operation,
        then server MUST return NFS4ERR_NOT_ONLY_OP. rfc5661 18.37.3

    FLAGS: destroy_session ganesha
    CODE: DSESS9005
    """
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()

    sid = sess1.sessionid
    res = c.c.compound([op.destroy_session(sess1.sessionid), op.putrootfh()])
    check(res, NFS4ERR_NOT_ONLY_OP)
