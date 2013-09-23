from st_create_session import create_session
from nfs4_const import *
from environment import check, fail, bad_sessionid, create_file
from nfs4_type import channel_attrs4
import nfs4_ops as op
import nfs4lib

def testSupported(t, env):
    """Do a simple SEQUENCE

    FLAGS: sequence all
    CODE: SEQ1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)

def testNotFirst(t, env):
    """SEQUENCE must be first

    FLAGS: sequence all
    CODE: SEQ2
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([sess.seq_op()])
    check(res, NFS4ERR_SEQUENCE_POS)

def testImplicitBind(t, env):
    """SEQUENCE sent on unbound connection will bind it if no enforcing done

    FLAGS: sequence all
    CODE: SEQ4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)

    # create an unbound connection
    rogue = env.c1.connect(env.c1.server_address)
    # send SEQUENCE2 over unbound connection 
    res = env.c1.compound([sess.seq_op()], pipe=rogue)
    check(res)
    
def testBadSession(t, env):
    """SEQUENCE sent on unknown session

    FLAGS: sequence all
    CODE: SEQ5
    """
    c = env.c1
    # SEQUENCE
    res = c.compound([op.sequence(bad_sessionid, 1, 0, 0, True)])
    check(res, NFS4ERR_BADSESSION)
    
def testRequestTooBig(t, env):
    """Send a request bigger than session can handle

    FLAGS: sequence all
    CODE: SEQ6
    """
    c1 = env.c1.new_client(env.testname(t))
    # Only allow 512 byte requests
    attrs = channel_attrs4(0, 512, 8192, 8192, 128, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send a lookup request with a very long filename
    res = sess1.compound([op.putrootfh(), op.lookup("12345"*100)])
    # FIXME - NAME_TOO_BIG is valid, don't want it to be
    check(res, NFS4ERR_REQ_TOO_BIG)

def testTooManyOps(t, env):
    """Send a request with more ops than the session can handle

    FLAGS: sequence all
    CODE: SEQ7
    """
    c1 = env.c1.new_client(env.testname(t))
    # Create session asking for 4 ops max per request
    attrs = channel_attrs4(0, 8192, 8192, 8192, 4, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send the max number of ops allowed by the server
    lots_of_ops = [op.putrootfh(), op.getfh()]
    lots_of_ops += [op.getattr(0) for num in xrange(sess1.fore_channel.maxoperations-3)]
    res = sess1.compound(lots_of_ops)
    check(res)
    # Add one more op to exceed the maximum
    lots_of_ops += [op.getattr(0)]
    res = sess1.compound(lots_of_ops)
    check(res, NFS4ERR_TOO_MANY_OPS)

def testBadSlot(t, env):
    """Send a request with a bad slot

    FLAGS: sequence all
    CODE: SEQ8
    """
    c1 = env.c1.new_client(env.testname(t))
    # Session has 8 slots (numbered 0 through 7)
    attrs = channel_attrs4(0, 8192, 8192, 8192, 128, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send sequence on (non-existant) slot number 8
    res = env.c1.compound([op.sequence(sess1.sessionid, 1, 8, 8, True)])
    check(res, NFS4ERR_BADSLOT)

def testReplayCache001(t, env):
    """Send two successful idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9a
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.putrootfh()], cache_this=True)
    check(res1)
    res2 = sess1.compound([op.putrootfh()], seq_delta=0)
    check(res2)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache002(t, env):
    """Send two successful non-idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9b
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, "%s_1" % env.testname(t))
    check(res)
    ops = env.home + [op.savefh(),\
          op.rename("%s_1" % env.testname(t), "%s_2" % env.testname(t))]
    res1 = sess1.compound(ops, cache_this=True)
    check(res1)
    res2 = sess1.compound(ops, seq_delta=0)
    check(res2)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache003(t, env):
    """Send two unsuccessful idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9c
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.putrootfh(), op.lookup("")], cache_this=True)
    check(res1, NFS4ERR_INVAL)
    res2 = sess1.compound([op.putrootfh(), op.lookup("")], seq_delta=0)
    check(res2, NFS4ERR_INVAL)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache004(t, env):
    """Send two unsuccessful non-idempotent compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9d
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = env.home
    ops += [op.savefh(), op.rename("", "foo")]
    res1 = sess1.compound(ops, cache_this=True)
    check(res1, NFS4ERR_INVAL)
    res2 = sess1.compound(ops, seq_delta=0)
    check(res2, NFS4ERR_INVAL)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache005(t, env):
    """Send two unsupported compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9e
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res1 = sess1.compound([op.illegal()], cache_this=True)
    check(res1, NFS4ERR_OP_ILLEGAL)
    res2 = sess1.compound([op.illegal()], seq_delta=0)
    check(res2, NFS4ERR_OP_ILLEGAL)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache006(t, env):
    """Send two solo sequence compounds with same seqid

    FLAGS: sequence all
    CODE: SEQ9f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res1 = sess.compound([])
    check(res1)
    res2 = sess.compound([], seq_delta=0)
    check(res2)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

def testReplayCache007(t, env):
    """Send two successful non-idempotent compounds with same seqid and False cache_this

    FLAGS: sequence all
    CODE: SEQ10b
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, "%s_1" % env.testname(t))
    check(res)
    ops = env.home + [op.savefh(),\
          op.rename("%s_1" % env.testname(t), "%s_2" % env.testname(t))]
    res1 = sess1.compound(ops, cache_this=False)
    check(res1, NFS4_OK)
    res2 = sess1.compound(ops, seq_delta=0, cache_this=False)
    check(res2, NFS4ERR_RETRY_UNCACHED_REP)

def testOpNotInSession(t, env):
    """Operations other than SEQUENCE, BIND_CONN_TO_SESSION, EXCHANGE_ID,
       CREATE_SESSION, and DESTROY_SESSION, MUST NOT appear as the
       first operation in a COMPOUND. rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ11
    """
    c = env.c1.new_client(env.testname(t))

    # putrootfh with out session
    res = c.c.compound([op.putrootfh()])
    check(res, NFS4ERR_OP_NOT_IN_SESSION)

def testSessionidSequenceidSlotid(t, env):
    """ The sr_sessionid result MUST equal sa_sessionid.
        The sr_slotid result MUST equal sa_slotid.
        The sr_sequenceid result MUST equal sa_sequenceid.
        rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ12
    """
    c = env.c1.new_client(env.testname(t))
    sess1 = c.create_session()

    # SEQUENCE
    sid = sess1.sessionid
    res = c.c.compound([op.sequence(sid, 1, 2, 3, True)])
    if not nfs4lib.test_equal(res.resarray[0].sr_sessionid, sid, "opaque"):
        fail("server return bad sessionid")

    if not nfs4lib.test_equal(res.resarray[0].sr_sequenceid, 1, "int"):
        fail("server return bad sequenceid")

    if not nfs4lib.test_equal(res.resarray[0].sr_slotid, 2, "int"):
        fail("server return bad slotid")

def testBadSequenceidAtSlot(t, env):
    """ If the difference between sa_sequenceid and the server's cached
        sequence ID at the slot ID is two (2) or more, or if sa_sequenceid
        is less than the cached sequence ID , server MUST return
        NFS4ERR_SEQ_MISORDERED. rfc5661 18.46.3

    FLAGS: sequence all
    CODE: SEQ13
    """
    c = env.c1.new_client(env.testname(t))
    # CREATE_SESSION
    sess1 = c.create_session()

    sid = sess1.sessionid
    res = c.c.compound([op.sequence(sid, 1, 2, 3, True)])
    check(res)

    seqid = res.resarray[0].sr_sequenceid
    # SEQUENCE with bad sr_sequenceid
    res = c.c.compound([op.sequence(sid, seqid + 2, 2, 3, True)])
    check(res, NFS4ERR_SEQ_MISORDERED)

    res = c.c.compound([op.sequence(sid, nfs4lib.dec_u32(seqid), 2, 3, True)])
    check(res, NFS4ERR_SEQ_MISORDERED)
