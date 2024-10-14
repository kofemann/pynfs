from .st_create_session import create_session
from .st_open import open_claim4
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file, do_getattrdict
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
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ|OPEN4_SHARE_ACCESS_WRITE,
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

def _testCbGetattr(t, env, change=0, size=0):
    cb = threading.Event()
    cbattrs = {}
    def getattr_post_hook(arg, env, res):
        res.obj_attributes = cbattrs
        env.notify = cb.set
        return res

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_post_hook(OP_CB_GETATTR, getattr_post_hook)

    res = sess1.compound([op.putrootfh(),
                          op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS,
                                                          FATTR4_OPEN_ARGUMENTS]))])
    check(res)
    caps = res.resarray[-1].obj_attributes

    openmask = (OPEN4_SHARE_ACCESS_READ  |
                OPEN4_SHARE_ACCESS_WRITE |
                OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)

    if caps[FATTR4_SUPPORTED_ATTRS] & FATTR4_OPEN_ARGUMENTS:
        if caps[FATTR4_OPEN_ARGUMENTS].oa_share_access_want & OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS:
            openmask |= 1<<OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS

    fh, deleg = __create_file_with_deleg(sess1, env.testname(t), openmask)
    print("__create_file_with_deleg: ", fh, deleg)
    attrs1 = do_getattrdict(sess1, fh, [FATTR4_CHANGE, FATTR4_SIZE,
                                        FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY])

    cbattrs[FATTR4_CHANGE] = attrs1[FATTR4_CHANGE]
    cbattrs[FATTR4_SIZE] = attrs1[FATTR4_SIZE]

    if change != 0:
        cbattrs[FATTR4_CHANGE] += 1
        if size > 0:
            cbattrs[FATTR4_SIZE] = size

    if openmask & 1<<OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS:
        cbattrs[FATTR4_TIME_DELEG_ACCESS] = attrs1[FATTR4_TIME_ACCESS]
        cbattrs[FATTR4_TIME_DELEG_MODIFY] = attrs1[FATTR4_TIME_MODIFY]
        if change != 0:
            cbattrs[FATTR4_TIME_DELEG_ACCESS].seconds += 1
            cbattrs[FATTR4_TIME_DELEG_MODIFY].seconds += 1

    # create a new client session and do a GETATTR
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    slot = sess2.compound_async([op.putfh(fh), op.getattr(1<<FATTR4_CHANGE | 1<<FATTR4_SIZE |
                                                          1<<FATTR4_TIME_ACCESS | 1<<FATTR4_TIME_MODIFY)])

    # wait for the CB_GETATTR
    completed = cb.wait(2)
    res = sess2.listen(slot)
    attrs2 = res.resarray[-1].obj_attributes
    sess1.compound([op.putfh(fh), op.delegreturn(deleg.write.stateid)])
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if not completed:
        fail("CB_GETATTR not received")
    return attrs1, attrs2

def testCbGetattrNoChange(t, env):
    """Test CB_GETATTR with no changes

    Get a write delegation, then do a getattr from a second client. Have the
    client regurgitate back the same attrs (indicating no changes). Then test
    that the attrs that the second client gets back match the first.

    FLAGS: deleg
    CODE: DELEG24
    """
    attrs1, attrs2 = _testCbGetattr(t, env)
    if attrs1[FATTR4_SIZE] != attrs2[FATTR4_SIZE]:
        fail("Bad size: %u != %u" % (attrs1[FATTR4_SIZE], attrs2[FATTR4_SIZE]))
    if attrs1[FATTR4_CHANGE] != attrs2[FATTR4_CHANGE]:
        fail("Bad change attribute: %u != %u" % (attrs1[FATTR4_CHANGE], attrs2[FATTR4_CHANGE]))
    if FATTR4_TIME_DELEG_MODIFY in attrs2:
        if attrs1[FATTR4_TIME_MODIFY] != attrs2[FATTR4_TIME_DELEG_MODIFY]:
            fail("Bad modify time: ", attrs1[FATTR4_TIME_MODIFY], " != ", attrs2[FATTR4_TIME_DELEG_MODIFY])

def testCbGetattrWithChange(t, env):
    """Test CB_GETATTR with simulated changes to file

    Get a write delegation, then do a getattr from a second client. Modify the
    attrs before sending them back to the server. Test that the second client
    sees different attrs than the original one.

    FLAGS: deleg
    CODE: DELEG25
    """
    attrs1, attrs2 = _testCbGetattr(t, env, change=1, size=5)
    if attrs2[FATTR4_SIZE] != 5:
        fail("Bad size: %u != 5" % attrs2[FATTR4_SIZE])
    if attrs1[FATTR4_CHANGE] == attrs2[FATTR4_CHANGE]:
        fail("Bad change attribute: %u == %u" % (attrs1[FATTR4_CHANGE], attrs2[FATTR4_CHANGE]))
    if FATTR4_TIME_DELEG_MODIFY in attrs2:
        if attrs1[FATTR4_TIME_MODIFY] == attrs2[FATTR4_TIME_DELEG_MODIFY]:
            fail("Bad modify time: ", attrs1[FATTR4_TIME_MODIFY], " == ", attrs2[FATTR4_TIME_DELEG_MODIFY])
