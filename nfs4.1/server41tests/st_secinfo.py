from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail, use_obj, bad_sessionid, create_file
from xdrdef.nfs4_type import channel_attrs4
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib

def testSupported(t, env):
    """Do a simple SECINFO

    FLAGS: all
    CODE: SEC1
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(env.testname(t))

    # Create a tmpfile for testing
    owner = b"owner_%s" % name
    path = sess.c.homedir + [name]
    res = create_file(sess, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Get the filehandle of the tmpfile's parent dir
    res = sess.compound(use_obj(sess.c.homedir) + [op.getfh()])
    check(res)
    fh_p = res.resarray[-1].object

    # Just do a simple SECINFO
    res = sess.compound([op.putfh(fh_p), op.secinfo(name)])
    check(res)

    # Cleanup
    res = sess.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)

def testSupported2(t, env):
    """GETFH after do a SECINFO_NO_NAME or SECINFO
       result in a NOFILEHANDLE error, See rfc 5661 section 2.6.3.1.1.8

    FLAGS: all
    CODE: SEC2
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(env.testname(t))

    # Create a tmpfile for testing
    owner = b"owner_%s" % name
    path = sess.c.homedir + [name]
    res = create_file(sess, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Get the filehandle of the tmpfile's parent dir
    res = sess.compound(use_obj(sess.c.homedir) + [op.getfh()])
    check(res)
    fh_p = res.resarray[-1].object

    # GETFH after do a SECINFO should get error NFS4ERR_NOFILEHANDLE
    res = sess.compound([op.putfh(fh_p), op.secinfo(name), op.getfh()])
    check(res, NFS4ERR_NOFILEHANDLE)

    # Cleanup
    res = sess.compound([op.putfh(fh), op.close(0, stateid)])
    check(res)
