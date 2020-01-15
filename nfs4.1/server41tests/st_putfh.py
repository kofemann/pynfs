from xdrdef.nfs4_const import *
from .environment import check, fail, use_obj, create_confirm, close_file
import nfs_ops
op = nfs_ops.NFS4ops()

def _try_put(t, sess, path):
    # Get fh via LOOKUP
    res = sess.compound(use_obj(path) + [op.getfh()])
    check(res)
    oldfh = res.resarray[-1].object
    # Now try PUTFH and GETFH, see if it agrees
    res = sess.compound([op.putfh(oldfh), op.getfh()])
    check(res)
    newfh = res.resarray[-1].object
    if oldfh != newfh:
        t.fail("GETFH did not return input of PUTFH for /%s" % '/'.join(path))

def testFile(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup file all
    CODE: PUTFH1r
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usefile)

def testLink(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup symlink all
    CODE: PUTFH1a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.uselink)

def testBlock(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup block all
    CODE: PUTFH1b
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.useblock)

def testChar(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup char all
    CODE: PUTFH1c
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usechar)

def testDir(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup dir all
    CODE: PUTFH1d
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usedir)

def testFifo(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup fifo all
    CODE: PUTFH1f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usefifo)

def testSocket(t, env):
    """PUTFH followed by GETFH should end up with original fh

    FLAGS: putfh getfh lookup socket all
    CODE: PUTFH1s
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    _try_put(t, sess, env.opts.usesocket)

def testBadHandle(t, env):
    """PUTFH with bad filehandle should return NFS4ERR_BADHANDLE

    FLAGS: putfh all
    CODE: PUTFH2
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = sess.compound([op.putfh(b'abc')])
    check(res, NFS4ERR_BADHANDLE, "PUTFH with bad filehandle='abc'")
