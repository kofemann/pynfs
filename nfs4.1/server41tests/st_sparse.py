from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail, create_file
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib

def testAllocateSupported(t, env):
    """Do a simple ALLOCATE
       send PUTROOTFH+ALLOCATE, check for legal result

    FLAGS: all sparse
    CODE: ALLOC1
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = create_file(sess, env.testname(t), access=OPEN4_SHARE_ACCESS_WRITE)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = sess.compound([op.putfh(fh), op.allocate(stateid, 0, 1)])
    check(res)

def testAllocateStateidZero(t, env):
    """Do a simple ALLOCATE with all-zero stateid

    FLAGS: all sparse
    CODE: ALLOC2
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = create_file(sess, env.testname(t), access=OPEN4_SHARE_ACCESS_WRITE)
    fh = res.resarray[-1].object

    res = sess.compound([op.putfh(fh), op.allocate(env.stateid0, 0, 1)])
    check(res)

def testAllocateStateidOne(t, env):
    """Do a simple ALLOCATE with all-one stateid

    FLAGS: all sparse
    CODE: ALLOC3
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = create_file(sess, env.testname(t), access=OPEN4_SHARE_ACCESS_WRITE)
    fh = res.resarray[-1].object

    res = sess.compound([op.putfh(fh), op.allocate(env.stateid1, 0, 1)])
    check(res)
