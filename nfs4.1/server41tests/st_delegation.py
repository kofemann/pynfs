from st_create_session import create_session
from st_open import open_claim4
from nfs4_const import *

from environment import check, checklist, fail, create_file, open_file, close_file
from nfs4_type import *
import nfs4_ops as op
import nfs4lib
import threading

def _got_deleg(deleg):
    return (deleg.delegation_type != OPEN_DELEGATE_NONE and
            deleg.delegation_type != OPEN_DELEGATE_NONE_EXT)

def __create_file_with_deleg(sess, name, access):
    res = create_file(sess, name, access = access)
    check(res)
    fh = res.resarray[-1].object
    deleg = res.resarray[-2].delegation
    if (not _got_deleg(deleg)):
        res = open_file(sess, name, access = access)
        fh = res.resarray[-1].object
        deleg = res.resarray[-2].delegation
        if (not _got_deleg(deleg)):
            fail("Could not get delegation")
    return (fh, deleg)

def _create_file_with_deleg(sess, name, access):
	fh, deleg = __create_file_with_deleg(sess, name, access)
	return fh

def _testDeleg(t, env, openaccess, want, breakaccess, sec = None, sec2 = None):
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        recall.cred = env.cred.raw_cred
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    sess1 = env.c1.new_client_session("%s_1" % env.testname(t), sec = sec)
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    if sec2:
        sess1.compound([op.backchannel_ctl(env.c1.prog, sec2)])
    fh = _create_file_with_deleg(sess1, env.testname(t), openaccess | want)
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
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(recall.stateid)])
    check(res)
    # Now get OPEN reply
    res = sess2.listen(slot)
    checklist(res, [NFS4_OK, NFS4ERR_DELAY])
    return recall

def testReadDeleg(t, env):
    """Test read delegation handout and return

    FLAGS: open deleg
    CODE: DELEG1
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH)

def testWriteDeleg(t, env):
    """Test write delegation handout and return

    FLAGS: writedelegations deleg
    CODE: DELEG2
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_WRITE,
       OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, OPEN4_SHARE_ACCESS_READ)

def testAnyDeleg(t, env):
    """Test any delegation handout and return

    FLAGS: open deleg
    CODE: DELEG3
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, OPEN4_SHARE_ACCESS_BOTH);

def testNoDeleg(t, env):
    """Test no delegation handout

    FLAGS: open deleg
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

    FLAGS: create_session open deleg
    CODE: DELEG5
    """
    uid = 17
    gid = 19
    sys_cred = authsys_parms(13, "fake name", uid, gid, [])
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec = [callback_sec_parms4(AUTH_SYS, sys_cred)])
    if recall.cred.body.uid != uid or recall.cred.body.gid != gid:
        fail("expected callback with uid, gid == %d, %d, got %d, %d"
                % (uid, gid, recall.cred.body.uid, recall.cred.body.gid))

def testCBSecParmsNull(t, env):
    """Test auth_null callbacks

    FLAGS: create_session open deleg
    CODE: DELEG6
    """
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec = [callback_sec_parms4(AUTH_NONE)])
    if recall.cred.flavor != AUTH_NONE:
        fail("expected callback flavor %d, got %d"
                % (AUTH_NONE, recall.cred.flavor))

def testCBSecParmsChange(t, env):
    """Test changing of auth_sys callbacks with backchannel_ctl

    FLAGS: create_session open deleg backchannel_ctl
    CODE: DELEG7
    """
    uid1 = 17
    gid1 = 19
    sys_cred1 = cbsp_sy_cred = authsys_parms(13, "fake name", uid1, gid1, [])
    uid2 = 29
    gid2 = 31
    sys_cred2 = cbsp_sy_cred = authsys_parms(13, "fake name", uid2, gid2, [])
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec  = [callback_sec_parms4(AUTH_SYS, sys_cred1)],
        sec2 = [callback_sec_parms4(AUTH_SYS, sys_cred2)])
    if recall.cred.body.uid != uid2 or recall.cred.body.gid != gid2:
        fail("expected callback with uid, gid == %d, %d, got %d, %d"
                % (uid2, gid2, recall.cred.body.uid, recall.cred.body.gid))

def testDelegRevocation(t, env):
    """Allow a delegation to be revoked, check that TEST_STATEID and
       FREE_STATEID have the required effect.

    FLAGS: deleg
    CODE: DELEG8
    """

    sess1 = env.c1.new_client_session("%s_1" % env.testname(t))
    fh, deleg = __create_file_with_deleg(sess1, env.testname(t),
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    delegstateid = deleg.read.stateid
    sess2 = env.c1.new_client_session("%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, "My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
                        owner, how, claim)
    while 1:
        res = sess2.compound(env.home + [open_op])
        if res.status == NFS4_OK:
            break;
        checklist(res, [NFS4_OK, NFS4ERR_DELAY])
	# just to keep sess1 renewed.  This is a bit fragile, as we
        # depend on the above compound waiting no longer than the
        # server's lease period:
        res = sess1.compound([])
    slot, seq_op = sess1._prepare_compound({})
    res = sess1.c.compound([seq_op])
    flags = res.resarray[0].sr_status_flags;
    if not(flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED):
        fail("SEQ4_STATUS_RECALLABLE_STATE_REVOKED should be set after"
             " sucess of open conflicting with delegation")
    flags &= ~SEQ4_STATUS_RECALLABLE_STATE_REVOKED
    if flags:
	print("WARNING: unexpected status flag(s) 0x%x set" % flags);
    res = sess1.update_seq_state(res, slot)
    res = sess1.compound([op.test_stateid([delegstateid])])
    stateid_stat = res.resarray[0].tsr_status_codes[0]
    if stateid_stat != NFS4ERR_DELEG_REVOKED:
        fail("TEST_STATEID on revoked stateid should report status"
             " NFS4ERR_DELEG_REVOKED, instead got %s" %
             nfsstat4[stateid_stat]);
    res = sess1.compound([op.free_stateid(delegstateid)])
    check(res)
    slot, seq_op = sess1._prepare_compound({})
    res = sess1.c.compound([seq_op])
    flags = res.resarray[0].sr_status_flags
    if flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED:
	fail("SEQ4_STATUS_RECALLABLE_STATE_REVOKED should be cleared after"
	     " FREE_STATEID")
    if flags & ~SEQ4_STATUS_RECALLABLE_STATE_REVOKED:
        print("WARNING: unexpected status flag(s) 0x%x set" % flags)
