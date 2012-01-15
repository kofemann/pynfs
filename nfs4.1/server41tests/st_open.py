from st_create_session import create_session
from nfs4_const import *

from environment import check, checklist, fail, create_file, open_file, close_file
from environment import open_create_file_op
from nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from nfs4_type import open_to_lock_owner4
import nfs4_ops as op
import threading

def expect(res, seqid):
    """Verify that open result has expected stateid.seqid"""
    got = res.resarray[-2].stateid.seqid
    if got != seqid:
        fail("Expected open_stateid.seqid == %i, got %i" % (seqid, got))

def testSupported(t, env):
    """Do a simple OPEN create

    FLAGS: open all
    CODE: OPEN1
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    # See 8.1.3.1 of draft-10:
    # the server MUST provide an "seqid" value starting at one...
    expect(res, seqid=1)

    # STUB - need to check  open_res.delegation.delegation_type
    # see draft-10 line 19445
    # QUESTION - what does "If the server supports the new _WANT_ flags" mean?
    #    will the server return INVAL? NOTSUPP? or just silently ignore?

def testServerStateSeqid(t, env):
    """Do multiple OPENs of a file, check that server bumps stateid.seqid

    FLAGS: open all
    CODE: OPEN2
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(name)
    owner = "owner_%s" % name
    path = sess1.c.homedir + [name]
    res = create_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    expect(res, seqid=1)
    res = open_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_READ)
    check(res)
    expect(res, seqid=2)
    # STUB - need to check no delegation return

# Test outdate, see draft22 8.2.2
def xtestClientStateSeqid(t, env):
    """Verify server enforce that client stateid.seqid==0

    See 8.1.3.1(draft-10): The client must...set the sequence value to zero.
    
    FLAGS: open all
    CODE: OPEN3
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(name)
    owner = "owner_%s" % name
    path = sess1.c.homedir + [name]
    res = create_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    expect(res, seqid=1)

    # Now use returned stateid (w/o zeroing seqid)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, "write test data")])
    check(res, NFS4ERR_BAD_STATEID, "Using an open_stateid w/o zeroing the seqid")
    

# Test outdated by draft15 8.8
def xtestOpenSeqid(t, env):
    """Verify server enforces seqid==0

    See 8.13(draft-10): Such vestigial fields in existing operations
                        should be set by the client to zero

    FLAGS: open all
    CODE: OPEN4
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(name)
    owner = "owner_%s" % name
    path = sess1.c.homedir + [name]
    res = create_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    expect(res, seqid=1)
    res = open_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_READ,
                    seqid=1)
    check(res, NFS4ERR_INVAL, msg="Using non-zero seqid in OPEN")
    
    
# Test outdated by draft15 8.8
def xtestOpenClientid(t, env):
    """Verify server enforces that open_owner.clientid==0

    See 8.13(draft-10): Such vestigial fields in existing operations
                        should be set by the client to zero
    
    FLAGS: open all
    CODE: OPEN5
    """
    name = env.testname(t)
    c1 = env.c1.new_client("%s_1" % name)
    if c1.clientid == 0:
        # If by coincidence clientid==0, make a new client
        c1 = env.c1.new_client("%s_2" % name)
    sess1 = c1.create_session()
    sess1.compound([op.reclaim_complete(FALSE)])
    res = create_file(sess1, env.testname(t), clientid=c1.clientid)
    check(res, NFS4ERR_INVAL, msg="Using non-zero clientid in open_owner")

def testReadDeleg(t, env):
    """Test read delgation handout and return

    FLAGS: open all
    CODE: OPEN20
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
    if deleg.delegation_type == OPEN_DELEGATE_NONE:
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

def testReadWrite(t, env):
    """Do a simple READ and WRITE

    FLAGS: open all
    CODE: OPEN30
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    owner = open_owner4(0, "My Open Owner")
    res = create_file(sess1, env.testname(t))
    check(res)
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    data = "write test data"
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, data)])
    check(res)
    res = sess1.compound([op.putfh(fh), op.read(stateid, 0, 1000)])
    check(res)
    if not res.resarray[-1].eof:
        fail("EOF not set on read")
    desired = "\0"*5 + data
    if res.resarray[-1].data != desired:
        fail("Expected %r, got %r" % (desired, res.resarray[-1].data))

def testEXCLUSIVE4AtNameAttribute(t, env):
    """If the file does exist,but the stored verifier does not match,
       then an error of NFS4ERR_EXIST is returned from server.
       rfc5661 18.16.3

    FLAGS: open all
    CODE: OPEN6
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1)
    check(res)

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1,
                        verifier = "Justtest")
    check(res, NFS4ERR_EXIST)

def testOPENClaimFH(t, env):
    """OPEN file with claim_type is CLAIM_FH

    FLAGS: open all
    CODE: OPEN7
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

    claim = open_claim4(CLAIM_FH)
    how = openflag4(OPEN4_NOCREATE)
    oowner = open_owner4(0, "My Open Owner 2")
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      oowner, how, claim)
    res = sess1.compound([op.putfh(fh), open_op])
    check(res)

    stateid = res.resarray[-1].stateid
    stateid.seqid = 0
    data = "write test data"
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, data)])
    check(res)
    res = sess1.compound([op.putfh(fh), op.read(stateid, 0, 1000)])
    check(res)
    if not res.resarray[-1].eof:
        fail("EOF not set on read")
    desired = "\0"*5 + data
    if res.resarray[-1].data != desired:
        fail("Expected %r, got %r" % (desired, res.resarray[-1].data))

