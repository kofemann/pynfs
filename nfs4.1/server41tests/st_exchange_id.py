from nfs4_const import *
import nfs4_ops as op
import time
from environment import check, checklist, fail
from nfs4_type import *
from rpc import RPCAcceptError, GARBAGE_ARGS, RPCTimeout
from nfs4lib import NFS4Error, hash_oids, encrypt_oids

def _getleasetime(sess):
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_LEASE_TIME)])
    return res.resarray[-1].obj_attributes[FATTR4_LEASE_TIME]

def _raw_exchange_id(c, name, verf=None, cred=None, protect=None, flags=0):
    if verf is None:
        verf = c.verifier
    owner = client_owner4(verf, name)
    if protect is None:
        protect = state_protect4_a(SP4_NONE)
    return c.compound([op.exchange_id(owner, flags, protect,
                                            [c.impl_id])], cred)

def testSupported(t, env):
    """Do a simple EXCHANGE_ID - no flags

    FLAGS: exchange_id all
    CODE: EID1
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, 0, protect, [c.impl_id])])
    check(res)
    # per draft 21 13.1, server MUST set one of these bits
    if not (res.resarray[0].eir_flags & EXCHGID4_FLAG_MASK_PNFS):
        fail("server did not set any EXCHGID4_FLAG_USE_* bits")


def testSupported1a(t, env):
    """Do a simple EXCHANGE_ID - simple flag

    FLAGS: exchange_id all
    CODE: EID1a
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, EXCHGID4_FLAG_USE_NON_PNFS, protect, [c.impl_id])])
    check(res)
    # per draft 21 13.1, server MUST set one of these bits
    if not (res.resarray[0].eir_flags & EXCHGID4_FLAG_MASK_PNFS):
        fail("server did not set any EXCHGID4_FLAG_USE_* bits")

def testSupported2(t, env):
    """Do an EXCHANGE_ID from within a session

    FLAGS: exchange_id all
    CODE: EID1b
    """
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    sess1 = c1.create_session()
    owner = client_owner4(sess1.c.verifier, "%s_2" % env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = sess1.compound([op.exchange_id(owner, EXCHGID4_FLAG_USE_PNFS_DS, protect, [sess1.c.impl_id])])
    check(res)
    # per draft 21 13.1, server MUST set one of these bits
    if not (res.resarray[0].eir_flags & EXCHGID4_FLAG_MASK_PNFS):
        fail("server did not set any EXCHGID4_FLAG_USE_* bits")


def testSSV(t, env):
    """Do a simple EXCHANGE_ID

    FLAGS: exchange_id all
    CODE: EID50
    """
    # E_ID with SP4_SSV set
    enforce = (1<<OP_CREATE_SESSION) | (1<<OP_BIND_CONN_TO_SESSION) | \
              (1<<OP_DESTROY_SESSION) | (1<<OP_DESTROY_CLIENTID) | \
              (1<<OP_BACKCHANNEL_CTL)
    allow = (1<<OP_CLOSE)
    oplists = state_protect_ops4(enforce, allow)
    ssv_parms = ssv_sp_parms4(oplists,
                              [hash_oids["sha256"], hash_oids["sha1"]],
                              ["giberrish_oid", encrypt_oids["aes256-CBC"]],
                              4, 2)
    protect = state_protect4_a(SP4_SSV, spa_ssv_parms=ssv_parms)
    c = env.c1.new_client(env.testname(t), protect=protect)

    sess = c.create_session() # Can we use ssv cred for cb_sec here?
    # This should fail if not using GSS?  What about E_ID?

    res = sess.set_ssv('\x5a' * c.protect.context.ssv_len)
    print res
    
def testNoImplId(t, env):
    """Do a simple EXCHANGE_ID w/o setting client impl_id

    FLAGS: exchange_id all
    CODE: EID2
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, 0, protect, [])])
    check(res)

def testLongArray(t, env):
    """Do a simple EXCHANGE_ID while setting impl_id array too long

    FLAGS: exchange_id all
    CODE: EID3
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    ops = [op.exchange_id(owner, 0, protect, [c.impl_id, c.impl_id])]
    xid = c.compound_async(ops, checks=False)
    try:
        res = c.listen(xid)
        print res
    except RPCAcceptError, e:
        if e.stat == GARBAGE_ARGS:
            # Legitimate return
            return
        else:
            raise
    check(res, NFS4ERR_BADXDR)
    
def testBadFlags(t, env):
    """Using an undefined flag bit should return _INVAL

    draft21 18.35.3 line 26458:
    Bits not defined above should not be set in the eia_flags field.  If
    they are, the server MUST reject the operation with NFS4ERR_INVAL.

    FLAGS: exchange_id all
    CODE: EID4
    """
    # STUB - want to send with various flags set
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, 4, protect, [c.impl_id])])
    check(res, NFS4ERR_INVAL, "Using undefined flag bit 0x4")


# Now test all possible combos of confirmed, update, verifier, and principle
# This is for draft-21
def testNoUpdate000(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5a
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf != old_verf, princ != old_princ
    # This is an example of case 4 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier(),
                           cred=env.cred2)
    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")

def testNoUpdate001(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5b
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf != old_verf, princ == old_princ
    # This is an example of case 4 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier(),
                           cred=env.cred1)
    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")
    return

def testNoUpdate010(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5c
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf == old_verf, princ != old_princ
    # This is an example of case 4 from draft 21
    c2 = env.c1.new_client(env.testname(t), cred=env.cred2)
    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")
    return

def testNoUpdate011(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5d
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf == old_verf, princ == old_princ
    # This is an example of case 4 from draft 21
    c2 = env.c1.new_client(env.testname(t), cred=env.cred1)
    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")
    return

def testNoUpdate100(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5e
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    res = c1.c.compound([op.destroy_session(sess1.sessionid)])
    check(res)
    # confirmed==True, verf != old_verf, princ != old_princ, no state
    # This is an example of case 3 from draft 21
    c2 = env.c1.new_client(env.testname(t), cred=env.cred2,
                           verf=env.new_verifier())
    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")
    # Check that cred1 state is destroyed
    res = c1._create_session()
    check(res, NFS4ERR_STALE_CLIENTID)

# Need similar tests of 100 for expired lease, existing state (IN_USE)

def testNoUpdate101(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5f
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()

    # confirmed==True, verf != old_verf, princ == old_princ
    # This is case 5 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier())

    if c1.clientid == c2.clientid:
        fail("Expected clientid %i to change" % c1.clientid)

    # Old session state should not be discarded until confirm:
    res = sess1.compound([])
    check(res)

    # Old session state should be discarded after confirm:
    sess2 = c2.create_session()
    check(res)
    res = sess1.compound([])
    check(res, NFS4ERR_BADSESSION)

def testNoUpdate101b(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5fb
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()

    # confirmed==True, verf != old_verf, princ == old_princ
    # This is case 5 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier())

    if c1.clientid == c2.clientid:
        fail("Expected clientid %i to change" % c1.clientid)

    sess2 = c2.create_session()

    # Old session state should be discarded:
    res = sess1.compound([])
    check(res, NFS4ERR_BADSESSION)

def testNoUpdate110(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5g
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    res = c1.c.compound([op.destroy_session(sess1.sessionid)])
    check(res)
    # confirmed==True, verf == old_verf, princ != old_princ
    # This is an example of case 3 from draft 21
    c2 = env.c1.new_client(env.testname(t), cred=env.cred2)

    if c2.clientid == c1.clientid:
        fail("Record replacement should create new clientid")
    # Check that cred1 state is destroyed
    res = sess1.compound([])
    check(res, NFS4ERR_BADSESSION)

# Need similar tests of 110 for expired lease, existing state (IN_USE)

def testNoUpdate111(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID5h
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    # confirmed==True, verf == old_verf, princ == old_princ
    # This is case 2 from draft 21
    c2 = env.c1.new_client(env.testname(t), cred=env.cred1)
    if c1.clientid != c2.clientid:
        fail("Expected clientid %i, got %i" % (c1.clientid, c2.clientid))
    # STUB - really want to check to see if E_ID results are the same

def testUpdateNonexistant(t, env):
    """Do an EXCHANGE_ID update of a non-existant record

    FLAGS: exchange_id all
    CODE: EID6
    """
    # This is part of case 7 of draft 21
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                                     protect, [c.impl_id])])
    check(res, NFS4ERR_NOENT, "Update a non-existant record")

def testUpdate000(t, env):
    """

    FLAGS: exchange_id all
    CODE: EID6a
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf != old_verf, princ != old_princ
    # This is an example of case 7 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier(),
                           cred=env.cred2,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_NOENT)

def testUpdate001(t, env):
    """

    FLAGS: exchange_id all
    CODE: EID6b
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf != old_verf, princ == old_princ
    # This is an example of case 7 from draft 21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier(),
                           cred=env.cred1,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_NOENT)

def testUpdate010(t, env):
    """

    FLAGS: exchange_id all
    CODE: EID6c
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf == old_verf, princ != old_princ
    # This is an example of case 7 from draft 21
    c2 = env.c1.new_client(env.testname(t),
                           cred=env.cred2,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_NOENT)

def testUpdate011(t, env):
    """

    FLAGS: exchange_id all
    CODE: EID6d
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    # confirmed==False, verf == old_verf, princ == old_princ
    # This is an example of case 7 from draft 21
    c2 = env.c1.new_client(env.testname(t),
                           cred=env.cred1,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_NOENT)

def testUpdate100(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID6e
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    # confirmed==True, verf != old_verf, princ != old_princ
    # This is an example of case 8 from draft-21
    res = _raw_exchange_id(env.c1, env.testname(t), verf=env.new_verifier(),
                           cred=env.cred2,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A)
    checklist(res, [NFS4ERR_NOT_SAME, NFS4ERR_PERM])
    
def testUpdate101(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID6f
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    # confirmed==True, verf != old_verf, princ == old_princ
    # This is an example of case 8 from draft-21
    c2 = env.c1.new_client(env.testname(t), verf=env.new_verifier(),
                           cred=env.cred1,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_NOT_SAME)
    
def testUpdate110(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID6g
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    # confirmed==True, verf == old_verf, princ != old_princ
    # This is an example of case 9 from draft-21
    c2 = env.c1.new_client(env.testname(t),
                           cred=env.cred2,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A,
                           expect=NFS4ERR_PERM)


def testUpdate111(t, env):
    """
    
    FLAGS: exchange_id all
    CODE: EID6h
    """
    c1 = env.c1.new_client(env.testname(t), cred=env.cred1)
    sess1 = c1.create_session()
    # confirmed==True, verf == old_verf, princ == old_princ
    # This is an example of case 6 from draft-21
    c2 = env.c1.new_client(env.testname(t),
                           cred=env.cred1,
                           flags=EXCHGID4_FLAG_UPD_CONFIRMED_REC_A)
    if c2.clientid != c1.clientid:
        fail("Record update changed clientid from %r to %r\n" %
             (c1.clientid, c2.clientid))
    # STUB - want to check update occurred

# Want test similar to testUpdate111, that tries to update qqc that cant update



# Want tests that test hash and encr alg arrays...test empty array,
# array containing only gibberish oids, and array containing
# valid oid after some gibberish, ensuring returned index points to
# 

def testSupported1a(t, env):
    """EXCHANGE_ID with server only flag 

    FLAGS: exchange_id all
    CODE: EID7
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, EXCHGID4_FLAG_USE_NON_PNFS | EXCHGID4_FLAG_CONFIRMED_R, protect, [c.impl_id])])
    check(res, NFS4ERR_INVAL)


def testNotOnlyOp(t, env):
    """Check for NFS4ERR_NOT_ONLY_OP

    FLAGS: exchange_id all
    CODE: EID8
    """
    c = env.c1
    owner = client_owner4(c.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    res = c.compound([op.exchange_id(owner, 0, protect, [c.impl_id]), op.putrootfh()])
    # per draft 21 18.35.3, server MUST return NFS4ERR_NOT_ONLY_OP
    check(res, NFS4ERR_NOT_ONLY_OP)

def testLeasePeriod(t, env):
    """Any unconfirmed record that is not confirmed within
       a lease period SHOULD be removed.

    FLAGS: exchange_id all
    CODE: EID9
    """
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    c2 = env.c1.new_client("%s_2" % env.testname(t))

    # Get server's lease time
    c3 = env.c1.new_client("%s_3" % env.testname(t))
    sess = c3.create_session()
    lease = _getleasetime(sess)

    # CREATE_SESSION
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    time.sleep(min(lease - 10, 1))
    # Inside lease period, create_session will success.
    res1 = c1.c.compound([op.create_session(c1.clientid, c1.seqid, 0,
                                        chan_attrs, chan_attrs,
                                        123, sec)], None)
    check(res1)

    time.sleep(lease + 10)
    # After lease period, create_session will get error NFS4ERR_STALE_CLIENTID
    res2 = c2.c.compound([op.create_session(c2.clientid, c2.seqid, 0,
                                        chan_attrs, chan_attrs,
                                        123, sec)], None)
    check(res2, NFS4ERR_STALE_CLIENTID)
