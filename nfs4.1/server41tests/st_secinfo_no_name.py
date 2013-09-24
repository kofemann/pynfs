from st_create_session import create_session
from nfs4_const import *
from environment import check, fail, bad_sessionid, create_file
from nfs4_type import channel_attrs4
import nfs4_ops as op
import nfs4lib

def testSupported(t, env):
    """Do a simple SECINFO_NO_NAME
       send PUTROOTFH+SECINFO_NO_NAME, check is result legal

    FLAGS: all secinfo_no_name
    CODE: SECNN1
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # Do a simple SECINFO_NO_NAME
    res = sess.compound([op.putrootfh(), op.secinfo_no_name(0)])
    check(res)

def testSupported2(t, env):
    """GETFH after do a SECINFO_NO_NAME or SECINFO
       result in a NOFILEHANDLE error, See rfc 5661 section 2.6.3.1.1.8

    FLAGS: all secinfo_no_name
    CODE: SECNN2
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # GETFH after do a SECINFO_NO_NAME should get error NFS4ERR_NOFILEHANDLE
    res = sess.compound([op.putrootfh(), op.secinfo_no_name(0), op.getfh()])
    print res
    check(res, NFS4ERR_NOFILEHANDLE)

def testSupported3(t, env):
    """Do a SECINFO_NO_NAME(SECINFO_STYLE4_PARENT) of root FH, expect NFS4ERR_NOENT
       send PUTROOTFH+SECINFO_NO_NAME(SECINFO_STYLE4_PARENT), check is result NOENT

    FLAGS: all secinfo_no_name
    CODE: SECNN3
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # Do a simple SECINFO_NO_NAME
    res = sess.compound([op.putrootfh(), op.secinfo_no_name(SECINFO_STYLE4_PARENT)])
    check(res, NFS4ERR_NOENT)

def testSupported4(t, env):
    """Do a SECINFO_NO_NAME(SECINFO_STYLE4_PARENT) of home
       send PUTROOTFH+SECINFO_NO_NAME(SECINFO_STYLE4_PARENT), check is result legal

    FLAGS: all secinfo_no_name
    CODE: SECNN4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()

    # Do a simple SECINFO_NO_NAME
    ops = env.home
    ops += [op.secinfo_no_name(SECINFO_STYLE4_PARENT)]
    res = sess.compound(ops)
    check(res)
