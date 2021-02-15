from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file, write_file, read_file
from .environment import open_create_file_op
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading
import nfs4lib

def expect(res, seqid):
    """Verify that open result has expected stateid.seqid"""
    got = res.resarray[-2].stateid.seqid
    if got != seqid:
        fail("Expected open_stateid.seqid == %i, got %i" % (seqid, got))

def testSupported(t, env):
    """Do a simple OPEN create

    FLAGS: open all
    CODE: OPEN1
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    # See 8.1.3.1 of draft-10:
    # the server MUST provide an "seqid" value starting at one...
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # STUB - need to check  open_res.delegation.delegation_type
    # see draft-10 line 19445
    # QUESTION - what does "If the server supports the new _WANT_ flags" mean?
    #    will the server return INVAL? NOTSUPP? or just silently ignore?

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testServerStateSeqid(t, env):
    """Do multiple OPENs of a file, check that server bumps stateid.seqid

    FLAGS: open all
    CODE: OPEN2
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(name)
    owner = b"owner_%s" % name
    path = sess1.c.homedir + [name]
    res = create_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    expect(res, seqid=1)
    res = open_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_READ)
    check(res)
    expect(res, seqid=2)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # STUB - need to check no delegation return

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testReadWrite(t, env):
    """Do a simple READ and WRITE

    FLAGS: open all
    CODE: OPEN30
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    owner = open_owner4(0, b"My Open Owner")
    res = create_file(sess1, env.testname(t))
    check(res)
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    data = b"write test data"
    res = write_file(sess1, fh, data, 5, stateid)
    check(res)
    res = read_file(sess1, fh, 0, 1000, stateid)
    check(res)
    if not res.eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.data != desired:
        fail("Expected %r, got %r" % (desired, res.data))

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testAnonReadWrite(t, env):
    """Do a simple READ and WRITE using anonymous stateid

    FLAGS: open all
    CODE: OPEN31
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    owner = open_owner4(0, b"My Open Owner")
    res = create_file(sess1, env.testname(t))
    check(res)
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    data = b"write test data"
    stateid = res.resarray[-2].stateid
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
    res = write_file(sess1, fh, data, 5, nfs4lib.state00)
    check(res)
    res = read_file(sess1, fh, 0, 1000, nfs4lib.state00)
    check(res)
    if not res.eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.data != desired:
        fail("Expected %r, got %r" % (desired, res.data))

def testEXCLUSIVE4AtNameAttribute(t, env):
    """If the file does exist,but the stored verifier does not match,
       then an error of NFS4ERR_EXIST is returned from server.
       rfc5661 18.16.3

    FLAGS: open all
    CODE: OPEN6
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1,
                        verifier = b"Justtest")
    check(res, NFS4ERR_EXIST)

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testOPENClaimFH(t, env):
    """OPEN file with claim_type is CLAIM_FH

    FLAGS: open all
    CODE: OPEN7
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False)
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

    claim = open_claim4(CLAIM_FH)
    how = openflag4(OPEN4_NOCREATE)
    oowner = open_owner4(0, b"My Open Owner 2")
    access = OPEN4_SHARE_ACCESS_BOTH|OPEN4_SHARE_ACCESS_WANT_NO_DELEG

    open_op = op.open(0, access, OPEN4_SHARE_DENY_NONE,
                      oowner, how, claim)
    res = sess1.compound([op.putfh(fh), open_op])
    check(res)

    stateid = res.resarray[-1].stateid
    stateid.seqid = 0
    data = b"write test data"
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, data)])
    check(res)
    res = sess1.compound([op.putfh(fh), op.read(stateid, 0, 1000)])
    check(res)
    if not res.resarray[-1].eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.resarray[-1].data != desired:
        fail("Expected %r, got %r" % (desired, res.resarray[-1].data))

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testCloseWithZeroSeqid(t, env):
    """OPEN followed by CLOSE with stateid.seq = 0

    FLAGS: open all
    CODE: OPEN8
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
