from xdrdef.nfs4_const import *
from .environment import check, fail, use_obj
import nfs_ops
op = nfs_ops.NFS4ops()

# NOTE: most of these require the --maketree to be run first
def testLookupp(t, env):
    """Basic Lookupp test

    FLAGS: lookupp all
    CODE: LKPP1d
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

def testFile(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp file all
    CODE: LKPP1r
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.usefile) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

def testFifo(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp fifo all
    CODE: LKPP1f
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.usefifo) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

def testLink(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp symlink all
    CODE: LKPP1a
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.uselink) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_SYMLINK, "LOOKUPP with non-dir <cfh>")

def testBlock(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp block all
    CODE: LKPP1b
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.useblock) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

def testChar(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp char all
    CODE: LKPP1c
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.usechar) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

def testSock(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp socket all
    CODE: LKPP1s
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = use_obj(env.opts.usesocket) + [op.lookupp()]
    res = sess1.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

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

def testXdev(t, env):
    """LOOKUPP with dir on different fs

    FLAGS: special
    CODE: LKPP4
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    ops = [op.putrootfh(), op.getfh()]
    op_pairs = [(op.lookup(component), op.getfh()) for component in env.opts.usespecial]
    ops += [op_pair[i] for op_pair in op_pairs for i in range(2)]
    ops += [op.lookupp(), op.getfh()]
    res = sess1.compound(ops)
    check(res)
    fh1 = res.resarray[-5].object
    fh2 = res.resarray[-1].object
    if fh1 != fh2:
        t.fail("file handles not equal")
