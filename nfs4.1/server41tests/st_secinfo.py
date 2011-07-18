from st_create_session import create_session
from nfs4_const import *
from environment import check, fail, use_obj, bad_sessionid, create_file
from nfs4_type import channel_attrs4
import nfs4_ops as op
import nfs4lib

def testSupported(t, env):
    """Do a simple SECINFO

    FLAGS: all
    CODE: SEC1
    """
    name = env.testname(t)
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # Create a tmpfile for testing
    owner = "owner_%s" % name
    path = sess.c.homedir + [name]
    res = create_file(sess, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)

    # Get the filehandle of the tmpfile's parent dir
    res = sess.compound(use_obj(sess.c.homedir) + [op.getfh()])
    check(res)
    fh = res.resarray[-1].object

    # Just do a simple SECINFO
    res = sess.compound([op.putfh(fh), op.secinfo(name)])
    check(res)

def testSupported2(t, env):
    """GETFH after do a SECINFO_NO_NAME or SECINFO
       result in a NOFILEHANDLE error, See rfc 5661 section 2.6.3.1.1.8

    FLAGS: all
    CODE: SEC2
    """
    name = env.testname(t)
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # Create a tmpfile for testing
    owner = "owner_%s" % name
    path = sess.c.homedir + [name]
    res = create_file(sess, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)

    # Get the filehandle of the tmpfile's parent dir
    res = sess.compound(use_obj(sess.c.homedir) + [op.getfh()])
    check(res)
    fh = res.resarray[-1].object

    # GETFH after do a SECINFO should get error NFS4ERR_NOFILEHANDLE
    res = sess.compound([op.putfh(fh), op.secinfo(name), op.getfh()])
    check(res, NFS4ERR_NOFILEHANDLE)
