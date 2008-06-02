from nfs4_const import *
from environment import check, fail
import nfs4_ops as op

# NOTE: most of these require the --maketree to be run first
def testLookupp(t, env):
    """Basic Lookupp test

    FLAGS: lookupp all
    CODE: LKPP1
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = []
    op_pairs = [(component, op.getfh()) for component in env.home]
    ops += [op_pair[i] for op_pair in op_pairs for i in range(2)]
    op_pairs = [op.lookupp(), op.getfh()]
    ops += [op_pairs[i] for component in env.home[:-1] for i in range(2)]
    res = sess1.compound(ops)
    check(res)
    for i in range(len(env.home)):
        if res.resarray[2*i+1].object != res.resarray[-(2*i+1)].object:
            t.fail('LOOKUPP returned %r, expected %r' %
                   (res.resarray[-(2*i+1)].object, res.resarray[2*i+1].object))

def testLookuppRoot(t, env):
    """Lookupp from root should return NFS4ERR_NOENT

    FLAGS: lookupp all
    CODE: LKPP2
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res = sess1.compound([op.putrootfh(), op.getfh()])
    check(res)
    fh = res.resarray[-1].object
    res = sess1.compound([op.putfh(fh), op.lookupp()])
    check(res, NFS4ERR_NOENT)

def testNoFH(t, env):
    """Lookup without a cfh should return NFS4ERR_NOFILEHANDLE

    FLAGS: lookupp all
    CODE: LKPP3
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    res = sess1.compound([op.lookupp()])
    check(res, NFS4ERR_NOFILEHANDLE)
