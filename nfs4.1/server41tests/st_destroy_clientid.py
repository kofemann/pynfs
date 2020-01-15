from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib

def testSupported(t, env):
    """ Do a simple DESTROY_CLIENTID
        destroy an unconfirmed clientid without session

    FLAGS: destroy_clientid all
    CODE: DESCID1
    """
    c = env.c1.new_client(env.testname(t))

    res = env.c1.compound([op.destroy_clientid(c.clientid)])
    check(res)

def testDestroyCIDWS(t, env):
    """ destroy an unconfirmed clientid with session

    FLAGS: destroy_clientid all
    CODE: DESCID2
    """
    c1 = env.c1.new_client(b"%s_1" % env.testname(t))
    c2 = env.c1.new_client(b"%s_2" % env.testname(t))
    sess = c1.create_session()

    res = sess.compound([op.destroy_clientid(c2.clientid)])
    check(res)

def testDestroyBadCIDWS(t, env):
    """ destroy a nonexistant clientid without session

    FLAGS: destroy_clientid all
    CODE: DESCID3
    """
    res = env.c1.compound([op.destroy_clientid(0)])
    check(res, NFS4ERR_STALE_CLIENTID)

def testDestroyBadCIDIS(t, env):
    """ destroy a nonexistant clientid in session

    FLAGS: destroy_clientid all
    CODE: DESCID4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    res = sess.compound([op.destroy_clientid(0)])
    check(res, NFS4ERR_STALE_CLIENTID)

def testDestroyCIDSessionB(t, env):
    """ destroy clientid using a session belong to that client

    FLAGS: destroy_clientid all
    CODE: DESCID5
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    res = sess.compound([op.destroy_clientid(c.clientid)])
    check(res, NFS4ERR_CLIENTID_BUSY)

def testDestroyCIDCSession(t, env):
    """ destroy a clientid which contains session without session

    FLAGS: destroy_clientid all
    CODE: DESCID6
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    res = env.c1.compound([op.destroy_clientid(c.clientid)])
    check(res, NFS4ERR_CLIENTID_BUSY)

def testDestroyCIDNotOnly(t, env):
    """ destroy a clientid without session with other compound

    FLAGS: destroy_clientid all
    CODE: DESCID7
    """
    res = env.c1.compound([op.destroy_clientid(0), op.reclaim_complete(TRUE)])
    check(res, NFS4ERR_NOT_ONLY_OP)

def testDestroyCIDTwice(t, env):
    """ destroy a clientid twice without session

    FLAGS: destroy_clientid all
    CODE: DESCID8
    """
    c = env.c1.new_client(env.testname(t))

    res = env.c1.compound([op.destroy_clientid(c.clientid)])
    check(res)

    res = env.c1.compound([op.destroy_clientid(c.clientid)])
    check(res, NFS4ERR_STALE_CLIENTID)
