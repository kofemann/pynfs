from nfs4_const import *
import nfs4_ops as op
from environment import check, fail
from nfs4_type import *
import random
import nfs4lib
from rpc import RPCAcceptError, GARBAGE_ARGS

def create_session(c, clientid, sequenceid, cred=None, flags=0):
    """Send a simple CREATE_SESSION"""
    chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
    res = c.compound([op.create_session(clientid, sequenceid, flags,
                                        chan_attrs, chan_attrs,
                                        123, [])], cred)
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
    cs_op = op.create_session(c1.clientid, c1.seqid, 0,
                              chan_attrs, chan_attrs, c1.c.prog, [])
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
    cs_op = op.create_session(c2.clientid, c2.seqid, 0,
                              chan_attrs, chan_attrs, c2.c.prog, [])
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
                             c.c.prog, [])]
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
        
