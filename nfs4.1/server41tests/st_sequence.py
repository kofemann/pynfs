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

def testNotBound(t, env):
    """SEQUENCE sent on unbound connection

    FLAGS: sequence all
    CODE: SEQ3
    """
    fail("TODO - need to set up state-protection")
    c = env.c1
    # EXCHANGE_ID
    eir = exchange_id(c, env.testname(t))
    # CREATE_SESSION, using connection binding
    res = create_session(c, eir.eir_clientid, eir.eir_sequenceid,
                         hashlist=[hash_algs["sha256"]])
    check(res)
    sid = res.resarray[0].csr_sessionid
    # SEQUENCE1
    res = c.compound([op.sequence(sid, 1, 0, 0, True)])
    check(res)
    # create an unbound connection
    rogue = c.connect(c.server_address)
    # send SEQUENCE2 over unbound connection 
    seqid = res.resarray[0].sr_sequenceid
    res = c.compound([op.sequence(sid, seqid, 0, 0, True)], pipe=rogue)
    check(res, NFS4ERR_CONN_NOT_BOUND_TO_SESSION)
    c.close(rogue)

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
    env.c1.close(rogue)
    
def testImplicitBind4a(t, env):
    """SEQUENCE sent on unbound connection will bind it if no enforcing done

    FLAGS: sequence all
    CODE: SEQ4a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)
    
    # create an unbound connection
    print "B1"
    rogue = env.c1.connect(env.c1.server_address)
    print "B2"
    # send SEQUENCE2 over unbound connection 
    res = env.c1.compound([sess.seq_op()], pipe=rogue)
    print "B3"
    check(res)
    print "B4"
    env.c1.close(rogue)
    print "B5"
    
def xtestImplicitBind(t, env):
    """SEQUENCE sent on unbound connection will bind it if no enforcing done

    FLAGS: sequence all
    CODE: SEQ4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([])
    check(res)

    c = env.c1
    # EXCHANGE_ID
    eir = exchange_id(c, env.testname(t))
    # CREATE_SESSION, using connection binding
    res = create_session(c, eir.eir_clientid, eir.eir_sequenceid)
    check(res)
    sid = res.resarray[0].csr_sessionid
    # SEQUENCE1
    res = c.compound([op.sequence(sid, 1, 0, 0, True)])
    check(res)
    # create an unbound connection
    rogue = c.connect(c.server_address)
    # send SEQUENCE2 over unbound connection 
    seqid = res.resarray[0].sr_sequenceid
    res = c.compound([op.sequence(sid, seqid, 0, 0, True)], pipe=rogue)
    check(res)
    c.close(rogue)
    
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
    # Only allow 4 ops per request
    attrs = channel_attrs4(0, 8192, 8192, 8192, 4, 8, [])
    sess1 = c1.create_session(fore_attrs = attrs)
    # Send a compound with 4 ops (counting sequence), should work
    res = sess1.compound([op.putrootfh(), op.getfh(), op.getattr(0)])
    check(res)
    # Send a compound with 5 ops (counting sequence), should fail
    res = sess1.compound([op.putrootfh(), op.getfh(), op.getattr(0),
                          op.getattr(0xf)])
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
    res1 = sess1.compound([op.putrootfh()])
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
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res = create_file(sess1, "%s_1" % env.testname(t))
    check(res)
    ops = env.home + [op.savefh(),\
          op.rename("%s_1" % env.testname(t), "%s_2" % env.testname(t))]
    res1 = sess1.compound(ops)
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
    res1 = sess1.compound([op.putrootfh(), op.lookup("")])
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
    ops = [op.putrootfh(), op.savefh(), op.rename("", "foo")]
    res1 = sess1.compound(ops)
    check(res1, NFS4ERR_INVAL)
    res2 = sess1.compound(ops, seq_delta=0)
    check(res2, NFS4ERR_INVAL)
    res1.tag = res2.tag = ""
    if not nfs4lib.test_equal(res1, res2):
        fail("Replay results not equal")

# XXX Need to test replay cache
# successful/unsuccessful idem/non-idem/non-supp
