from .st_create_session import create_session
from .st_open import open_claim4
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()
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
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t), sec = sec)
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    if sec2:
        sess1.compound([op.backchannel_ctl(env.c1.prog, sec2)])
    fh = _create_file_with_deleg(sess1, env.testname(t), openaccess | want)
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, breakaccess, OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    # Wait for recall, and return delegation
    completed = recall.wait(2)
    # Getting here means CB_RECALL reply is in the send queue.
    # Give it a moment to actually be sent
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(recall.stateid)])
    check(res)
    # Now get OPEN reply
    res = sess2.listen(slot)
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if not completed:
        fail("delegation break not received")
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
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
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
    sys_cred = authsys_parms(13, b"fake name", uid, gid, [])
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
    sys_cred1 = cbsp_sy_cred = authsys_parms(13, b"fake name", uid1, gid1, [])
    uid2 = 29
    gid2 = 31
    sys_cred2 = cbsp_sy_cred = authsys_parms(13, b"fake name", uid2, gid2, [])
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

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    fh, deleg = __create_file_with_deleg(sess1, env.testname(t),
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    delegstateid = deleg.read.stateid
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
                        owner, how, claim)
    while 1:
        res = sess2.compound(env.home + [open_op])
        if res.status == NFS4_OK:
            break;
        check(res, [NFS4_OK, NFS4ERR_DELAY])
        # just to keep sess1 renewed.  This is a bit fragile, as we
        # depend on the above compound waiting no longer than the
        # server's lease period:
        res = sess1.compound([])
    res = sess1.compound([op.putfh(fh), op.read(delegstateid, 0, 1000)])
    check(res, NFS4ERR_DELEG_REVOKED, "Read with a revoked delegation")
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

def testWriteOpenvsReadDeleg(t, env):
    """Ensure that a write open prevents granting a read delegation

    FLAGS: deleg
    CODE: DELEG9
    """

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    owner = b"owner_%s" % env.testname(t)
    res = create_file(sess1, owner, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)

    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    access = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG;
    res = open_file(sess2, owner, access = access)
    check(res)

    deleg = res.resarray[-2].delegation
    if (not _got_deleg(deleg)):
        res = open_file(sess2, owner, access = access)
        fh = res.resarray[-1].object
        deleg = res.resarray[-2].delegation
    if (_got_deleg(deleg)):
        fail("Granted delegation to a file write-opened by another client")

def testServerSelfConflict3(t, env):
    """DELEGATION test

    Get a read delegation, then do a write open from the same client.
    That should succeed.  Then do a write open from a different client,
    and verify that it breaks the delegation.

    FLAGS: deleg
    CODE: DELEG23
    """

    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid
        recall.cred = env.cred.raw_cred
        env.notify = recall.set
    def post_hook(arg, env, res):
        return res
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)

    fh, deleg = __create_file_with_deleg(sess1, env.testname(t),
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    print("__create_file_with_deleg: ", fh, deleg)
    delegstateid = deleg.read.stateid
    res = open_file(sess1, env.testname(t), access = OPEN4_SHARE_ACCESS_WRITE)
    print("open_file res: ", res)
    check(res)

    # XXX: cut-n-paste from _testDeleg; make helper instead:
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"owner")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    completed = recall.wait(2)
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(delegstateid)])
    check(res)
    res = sess2.listen(slot)
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if not completed:
        fail("delegation break not received")
