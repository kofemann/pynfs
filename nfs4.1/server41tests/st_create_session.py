from xdrdef.nfs4_const import *
import nfs_ops
op = nfs_ops.NFS4ops()
from environment import check, fail, create_file, open_file
from xdrdef.nfs4_type import *
import random
import nfs4lib
import threading
from rpc import RPCAcceptError, GARBAGE_ARGS

def create_session(c, clientid, sequenceid, cred=None, flags=0):
    """Send a simple CREATE_SESSION"""
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    res = c.compound([op.create_session(clientid, sequenceid, flags,
                                        chan_attrs, chan_attrs,
                                        123, [callback_sec_parms4(0)])], cred)
    return res

###############################################

def testSupported1(t, env):
    """Do a simple CREATE_SESSION

    FLAGS: create_session all
    CODE: CSESS1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

def testSupported2(t, env):
    """Do a CREATE_SESSION after a SEQUENCE (for same client)

    FLAGS: create_session all
    CODE: CSESS2
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    # Create second session
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    cs_op = op.create_session(c1.clientid, c1.seqid, 0,
                              chan_attrs, chan_attrs, c1.c.prog, sec)
    res = sess1.compound([cs_op])
    check(res)
    sess2 = c1._add_session(res.resarray[-1])
    # Now make sure sess2 works
    res = sess2.compound([op.putrootfh()])
    check(res)
    
def testSupported2b(t, env):
    """Do a CREATE_SESSION after a SEQUENCE (for different client)

    FLAGS: create_session all
    CODE: CSESS2b
    """
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    c2 = env.c1.new_client("%s_2" % env.testname(t))
    sess1 = c1.create_session()
    # Create second session
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    cs_op = op.create_session(c2.clientid, c2.seqid, 0,
                              chan_attrs, chan_attrs, c2.c.prog, sec)
    res = sess1.compound([cs_op])
    check(res)
    sess2 = c2._add_session(res.resarray[-1])
    # Now make sure sess2 works
    res = sess2.compound([op.putrootfh()])
    check(res)
    
def testNoExchange(t, env):
    """Send CREATE_SESSION when server has no record of clientid

    FLAGS: create_session all
    CODE: CSESS3
    """
    c = env.c1
    # NOTE no real way to guarantee this will not collide with previously
    # seen clientid, but odds are pretty low.
    cid = random.randint(0, 2**64 - 1)
    res = create_session(c, cid, 256)
    check(res, NFS4ERR_STALE_CLIENTID)

def testContrivedReplay(t, env):
    """Server is supposed to create a contrived replay result

    FLAGS: create_session all
    CODE: CSESS4
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    res = create_session(c.c, c.clientid,
                         nfs4lib.dec_u32(c.seqid))
    check(res, NFS4ERR_SEQ_MISORDERED)

def testReplay1(t, env):
    """Replay a successful CREATE_SESSION
    
    FLAGS: create_session all
    CODE: CSESS5
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    res1 = create_session(c.c, c.clientid, c.seqid)
    check(res1)
    # REPLAY
    res2 = create_session(c.c, c.clientid, c.seqid)
    check(res2)
    # Test results are equal (ignoring tags)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplay1a(t, env):
    """Replay a successful CREATE_SESSION with a SEQUENCE from a different session

    FLAGS: create_session all
    CODE: CSESS5a
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    sess1 = c.create_session()
    # another CREATE_SESSION
    c.seqid = 2
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    res1 = create_session(c.c, c.clientid, c.seqid)
    check(res1)
    # REPLAY first CREATE_SESSION with SEQUENCE from 2nd session
    cs_op = op.create_session(c.clientid, c.seqid, 0,
                              chan_attrs, chan_attrs, c.c.prog, sec)
    res2 = sess1.compound([cs_op])
    check(res2)
    # Test results are equal (ignoring tags)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplay1b(t, env):
    """Replay a successful SEQUENCE:CREATE_SESSION without a preceeding SEQUENCE

    FLAGS: create_session all
    CODE: CSESS5b
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    sess1 = c.create_session()
    # another CREATE_SESSION with SEQUENCE from first session
    c.seqid = 2
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    sec = [callback_sec_parms4(0)]
    cs_op = op.create_session(c.clientid, c.seqid, 0,
                              chan_attrs, chan_attrs, c.c.prog, sec)
    res1 = sess1.compound([cs_op])
    check(res1)
    # REPLAY second CREATE_SESSION without SEQUENCE
    res2 = create_session(c.c, c.clientid, c.seqid)
    check(res2)
    # Test results are equal (ignoring tags)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplay2(t, env):
    """Replay a unsuccessful CREATE_SESSION
    
    FLAGS: create_session all
    DEPEND: CSESS9
    CODE: CSESS6
    """
    c = env.c1.new_client(env.testname(t), cred=env.cred1)
    res1 = create_session(c.c, c.clientid, c.seqid, cred=env.cred2)
    check(res1, NFS4ERR_CLID_INUSE)
    # REPLAY
    res2 = create_session(c.c, c.clientid, c.seqid, cred=env.cred2)
    check(res2, NFS4ERR_CLID_INUSE)
    # Test results are equal (ignoring tags)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testBadSeqnum1(t, env):
    """Send too large seqnum
    
    FLAGS: create_session all
    CODE: CSESS7
    """
    c = env.c1.new_client(env.testname(t))
    res1 = create_session(c.c, c.clientid, c.seqid)
    check(res1)
    # REPLAY
    badseqid = nfs4lib.inc_u32(nfs4lib.inc_u32(c.seqid))
    res2 = create_session(c.c, c.clientid, badseqid)
    check(res2, NFS4ERR_SEQ_MISORDERED)

def testBadSeqnum2(t, env):
    """Send too small seqnum
    
    FLAGS: create_session all
    CODE: CSESS8
    """
    c = env.c1.new_client(env.testname(t))
    res1 = create_session(c.c, c.clientid, c.seqid)
    check(res1)
    # REPLAY
    badseqid = nfs4lib.dec_u32(c.seqid)
    res2 = create_session(c.c, c.clientid, badseqid)
    check(res2, NFS4ERR_SEQ_MISORDERED)

def testPrincipalCollision1(t, env):
    """Change of principal before confirmation is bad
    
    FLAGS: create_session all
    CODE: CSESS9
    """
    c = env.c1.new_client(env.testname(t), cred=env.cred1)
    res = create_session(c.c, c.clientid, c.seqid, cred=env.cred2)
    check(res, NFS4ERR_CLID_INUSE)

def testPrincipalCollision2(t, env):
    """Change of principal after confirmation is good
    
    FLAGS: create_session all
    CODE: CSESS10
    """
    c = env.c1.new_client(env.testname(t), cred=env.cred1)
    res1 = create_session(c.c, c.clientid, c.seqid, cred=env.cred1)
    check(res1)
    csr = res1.resarray[0]
    res2 = create_session(c.c, c.clientid, csr.csr_sequence,
                          cred=env.cred2)
    check(res2)

def testBadFlag(t, env):
    """Use invalid flag bits

    FLAGS: create_session all
    CODE: CSESS15
    """
    c = env.c1.new_client(env.testname(t))
    res = create_session(c.c, c.clientid, c.seqid, flags = 0xf)
    # XXX Where is this required?  What about ignoring bits?
    check(res, NFS4ERR_INVAL)

def testCbSecParms(t, env):
    """Send each type of security parameter

    NOTE this is a bit strange, no one would really send mixture
    FLAGS: create_session all
    CODE: CSESS16
    """
    sec = [callback_sec_parms4(AUTH_NONE),
           callback_sec_parms4(AUTH_SYS, cbsp_sys_cred=authsys_parms(5, "Random machine name", 7, 11, [13, 17, 19, 23, 29])),
           callback_sec_parms4(RPCSEC_GSS, cbsp_gss_handles=gss_cb_handles4(RPC_GSS_SVC_PRIVACY, "Handle from server", "Client handle")),
           ]
                               
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session(sec=sec)

def testCbSecParmsDec(t, env):
    """A decode problem was found at NFS server
       (wrong index used in inner loop).
       http://marc.info/?l=linux-kernel&m=129961996327640&w=2

    FLAGS: create_session all
    CODE: CSESS16a
    """
    sec = [callback_sec_parms4(AUTH_NONE),
           callback_sec_parms4(RPCSEC_GSS, cbsp_gss_handles=gss_cb_handles4(RPC_GSS_SVC_PRIVACY, "Handle from server", "Client handle")),
           callback_sec_parms4(AUTH_SYS, cbsp_sys_cred=authsys_parms(5, "Random machine name", 7, 11, [])),
           ]

    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session(sec=sec)

def testRdmaArray0(t, env):
    """Test 0 length rdma arrays

    FLAGS: create_session all
    CODE: CSESS17
    """
    c1 = env.c1.new_client(env.testname(t))
    chan_attrs = channel_attrs4(0, 8192,8192,8192,128,8,[])
    sess1 = c1.create_session(fore_attrs=chan_attrs,
                              back_attrs=chan_attrs)

def testRdmaArray1(t, env):
    """Test length 1 rdma arrays

    FLAGS: create_session all
    CODE: CSESS18
    """
    c1 = env.c1.new_client(env.testname(t))
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[57])
    sess1 = c1.create_session(fore_attrs=chan_attrs,
                              back_attrs=chan_attrs)

def testRdmaArray2(t, env):
    """Test length 2 rdma arrays

    FLAGS: create_session all
    CODE: CSESS19
    """
    c = env.c1.new_client(env.testname(t))
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[13, 57])
    ops = [op.create_session(c.clientid, c.seqid, 0,
                             chan_attrs, chan_attrs,
                             c.c.prog, [callback_sec_parms4(0)])]
    c = c.c
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

def testManyClients(t, env):
    """Create and confirm many clients

    FLAGS: create_session all
    CODE: CSESS200
    """
    N = 10 # number of clients to create
    for i in range(N):
        c = env.c1.new_client("%s_Client_%i" % (env.testname(t), i))
        sess = c.create_session()
        
def testCallbackProgram(t, env):
    """Check server can handle random transient program number

    FLAGS: ganesha
    CODE: CSESS20
    """
    cb_occurred = threading.Event()
    transient = 0x40000004
    def mycheck(prog):
        print "Got call using prog=0x%x" % prog
        cb_occurred.prog = prog
        cb_occurred.set()
        return True;
    orig = env.c1._check_program
    try:
        env.c1._check_program = mycheck
        c = env.c1.new_client(env.testname(t))
        sess = c.create_session(prog=transient)
        cb_occurred.wait(10)
        if not cb_occurred.isSet():
            fail("No CB_NULL sent")
        if cb_occurred.prog != transient:
            fail("Expected cb progam 0x%x, got 0x%x" %
                 (transient, cb_occurred.prog))
    finally:
        env.c1._check_program = orig

def testCallbackVersion(t, env):
    """Check server sends callback program with a version listed in nfs4client.py

    FLAGS: ganesha
    CODE: CSESS21
    """
    cb_occurred = threading.Event()
    transient = 0x40000000
    def mycheck(low, hi, vers):
        print "Got call using version=%i" % vers
        cb_occurred.low = low
        cb_occurred.hi = hi
        cb_occurred.vers = vers
        cb_occurred.set()
        return (low <= vers <= hi)
    orig = env.c1._check_version
    try:
        env.c1._check_version = mycheck
        c = env.c1.new_client(env.testname(t))
        sess = c.create_session(prog=transient)
        cb_occurred.wait(10)
        if not cb_occurred.isSet():
            fail("No CB_NULL sent")
        if not (cb_occurred.low <= cb_occurred.vers <= cb_occurred.hi):
            fail("Expected cb version between %i and %i, got %i" %
                 (cb_occurred.low, cb_occurred.hi, cb_occurred.vers))
    finally:
        env.c1._check_version = orig

def testMaxreqs(t, env):
    """A CREATE_SESSION with maxreqs too large should return
       a modified value

    FLAGS: create_session all
    CODE: CSESS22
    """
    # Assuming this is too large for any server; increase if necessary:
    # but too huge will eat many memory for replay_cache, be careful!
    TOO_MANY_SLOTS = 500

    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION with fore_channel = TOO_MANY_SLOTS
    chan_attrs = channel_attrs4(0,8192,8192,8192,128, TOO_MANY_SLOTS, [])
    sess1 = c.create_session(fore_attrs=chan_attrs)
    if nfs4lib.test_equal(sess1.fore_channel.maxrequests,
                          chan_attrs.ca_maxrequests, "count4"):
        fail("Server allows surprisingly large fore_channel maxreqs")

def testNotOnlyOp(t, env):
    """Check for NFS4ERR_NOT_ONLY_OP

    FLAGS: create_session all
    CODE: CSESS23
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION with PUT_ROOTFH
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                        chan_attrs, chan_attrs,
                                        123, []), op.putrootfh()], None)
    check(res, NFS4ERR_NOT_ONLY_OP)

def testCsr_sequence(t, env):
    """The corresponding result of csa_sequence is csr_sequence,
       which MUST be equal to csa_sequence.

    FLAGS: create_session all
    CODE: CSESS24
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    csa_sequence = c.seqid
    sess1 = c.create_session(fore_attrs=chan_attrs)
    if not nfs4lib.test_equal(sess1.seqid, csa_sequence, "int"):
        fail("Server returns bad csr_sequence which not equal to csa_sequence")

def testTooSmallMaxRS(t, env):
    """If client selects a value for ca_maxresponsesize such that
       a replier on a channel could never send a response,
       server SHOULD return NFS4ERR_TOOSMALL

    FLAGS: create_session all
    CODE: CSESS25
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION with too small ca_maxresponsesize
    chan_attrs = channel_attrs4(0,8192,0,8192,128,8,[])
    res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                        chan_attrs, chan_attrs,
                                        123, [])], None)
    check(res, NFS4ERR_TOOSMALL)

def testRepTooBig(t, env):
    """If requester sends a request for which the size of the reply
       would exceed ca_maxresponsesize, the replier will return
       NFS4ERR_REP_TOO_BIG

    FLAGS: create_session all
    CODE: CSESS26
    """
    name = env.testname(t)
    c1 = env.c1.new_client(name)
    # create session with a small ca_maxresponsesize
    chan_attrs = channel_attrs4(0,400,400,400,128,8,[])
    sess1 = c1.create_session(fore_attrs=chan_attrs)
    sess1.compound([op.reclaim_complete(FALSE)])

    mandatory = [attr.bitnum for attr in env.attr_info if attr.mandatory]
    print(mandatory);
    ops = [op.putrootfh()]
    getattrop = op.getattr(nfs4lib.list2bitmap(mandatory))
    ops += [getattrop, getattrop, getattrop, getattrop]
    res = sess1.compound(ops)
    check(res, NFS4ERR_REP_TOO_BIG)

def testRepTooBigToCache(t, env):
    """If requester sends a request for which the size of the reply
       would exceed ca_maxresponsesize_cached, the replier will return
       NFS4ERR_REP_TOO_BIG_TO_CACHE

    FLAGS: create_session all
    CODE: CSESS27
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION with a small ca_maxresponsesize_cached
    chan_attrs = channel_attrs4(0,8192,8192,10,128,8,[])
    res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                        chan_attrs, chan_attrs,
                                        123, [])], None)
    check(res)

    # SEQUENCE with cache this
    sid = res.resarray[0].csr_sessionid
    res = c.c.compound([op.sequence(sid, 1, 0, 0, True)])
    check(res, NFS4ERR_REP_TOO_BIG_TO_CACHE)

def testTooSmallMaxReq(t, env):
    """If client selects a value for ca_maxrequestsize such that
       a replier on a channel could never send a request,
       server SHOULD return NFS4ERR_TOOSMALL

    FLAGS: create_session all
    CODE: CSESS28
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION with too small ca_maxrequestsize
    chan_attrs = channel_attrs4(0,20,8192,8192,128,8,[])
    res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                          chan_attrs, chan_attrs,
                                          123, [])], None)
    check(res, NFS4ERR_TOOSMALL)

def testDRCMemLeak(t, env):
    """Test whether the replier put drc mem after checking back
       channel attrs failed.

    FLAGS: create_session all
    CODE: CSESS29
    """
    c = env.c1.new_client(env.testname(t))
    fchan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    # CREATE_SESSION with too small ca_maxrequestsize and ca_maxops
    bchan_attrs = channel_attrs4(0,10,8192,8192,128,1,[])

    N = 10000 # number of clients to create, all will denied with TOOSMALL
    for i in range(N):
        res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                              fchan_attrs, bchan_attrs,
                                              123, [])], None)
        check(res, NFS4ERR_TOOSMALL)

    bchan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    res = c.c.compound([op.create_session(c.clientid, c.seqid, 0,
                                          fchan_attrs, bchan_attrs,
                                          123, [])], None)
    check(res, NFS4_OK)
