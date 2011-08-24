from st_create_session import create_session
from nfs4_const import *
from environment import check, fail
import nfs4_ops as op
import nfs4lib

def testSupported(t, env):
    """Do a simple RECLAIM_COMPLETE

    FLAGS: reclaim_complete all
    CODE: RECC1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    res = sess.compound([op.putrootfh(), op.reclaim_complete(TRUE)])
    check(res)

    res = sess.compound([op.reclaim_complete(FALSE)])
    check(res)
