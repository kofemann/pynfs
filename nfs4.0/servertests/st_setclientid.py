from xdrdef.nfs4_const import *
from .environment import check
import os
import struct, time
import nfs_ops
op = nfs_ops.NFS4ops()

def _checkprinciples(t, env):
    """Make sure c1 and c2 have different principles"""
    # STUB
    return True

def testValid(t, env):
    """SETCLIENTID simple call

    FLAGS: setclientid setclientidconfirm all
    CODE: INIT
    """
    env.c1.init_connection()

def testClientReboot(t, env):
    """SETCLIENTID - create a stale client id and use it

    Note CLOSE does not have NFS4ERR_STALE_CLIENTID

    FLAGS: setclientid setclientidconfirm all
    DEPEND: INIT MKFILE
    CODE: CID1
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    # This should clean out client state, invalidating stateid
    c.init_connection(verifier=b'')
    res = c.close_file(t.word(), fh, stateid)
    check(res, NFS4ERR_EXPIRED,
          "Trying to use old stateid after SETCLIENTID_CONFIRM purges state")
    
def testClientUpdateCallback(t, env):
    """SETCLIENTID - make sure updating callback info does not invalidate state

    FLAGS: setclientid setclientidconfirm all
    DEPEND: INIT MKFILE
    CODE: CID1b
    """
    c = env.c1
    id = b'pynfs%i_%s' % (os.getpid(), t.word())
    verf = struct.pack('>d', time.time())
    c.init_connection(id, verf)
    fh, stateid = c.create_confirm(t.word())
    c.init_connection(id, verf)
    res = c.close_file(t.word(), fh, stateid)
    check(res, msg="Close after updating callback info")
    
def testNotInUse(t, env):
    """SETCLIENTID with same nfs_client_id.id should return NFS4ERR_OK
       if there is no active state

    This requires NCL1 and NCL2 to have different principals (UIDs).
    
    FLAGS: setclientid setclientidconfirm all
    DEPEND: _checkprinciples INIT
    CODE: CID2
    """
    c1 = env.c1
    c2 = env.c2
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())
    c1.init_connection(clid, verifier=c1.verifier)
    ops = [c2.setclientid(clid, verifier=c1.verifier)]
    res = c2.compound(ops)
    check(res, NFS4_OK, "SETCLIENTID with same nfs_client_id.id")
    
def testInUse(t, env):
    """SETCLIENTID with same nfs_client_id.id should return NFS4ERR_CLID_INUSE
       if there is active state

    This requires NCL1 and NCL2 to have different principals (UIDs).
    
    FLAGS: setclientid setclientidconfirm all
    DEPEND: _checkprinciples INIT
    CODE: CID2a
    """
    c1 = env.c1
    c2 = env.c2
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())
    c1.init_connection(clid, verifier=c1.verifier)
    c1.create_confirm(t.word())
    ops = [c2.setclientid(clid, verifier=c1.verifier)]
    res = c2.compound(ops)
    check(res, NFS4ERR_CLID_INUSE, "SETCLIENTID with same nfs_client_id.id")
    
def testLoseAnswer(t, env):
    """SETCLIENTID after a client reboot could cause case not covered in RFC

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID3
    """
    c = env.c1
    id = b"Clientid_for_%s_pid=%i" % (t.word(), os.getpid())
    c.init_connection(id)
    res = c.compound([c.setclientid(id=id)])
    check(res)
    # Now assume client reboot, id should stay same, but verifier changes,
    # and we have lost result from second setclientid.
    # This case is not covered in RFC 3530, but should return OK.
    res = c.compound([c.setclientid(id=id, verifier=b'')])
    check(res, msg="SETCLIENTID case not covered in RFC")
    
def testAllCases(t, env):
    """SETCLIENTID with each case from RFC

    Note: This just runs through the cases, but there seems to be no
    way to check that server is actually doing the correct thing.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4
    """
    c = env.c1
    id = b"Clientid_for_%s_pid=%i" % (t.word(), os.getpid())
    # no (*x***), no (*x****)
    res = c.compound([c.setclientid(id=id)])
    check(res)
    # no (*x***), (*x****)
    c.init_connection(id)
    # (vxc**), no (vxc**)
    res = c.compound([c.setclientid(id=id)])
    check(res)
    # (vxc**), (vxc**)
    c.init_connection(id)
    # (*x***), no (*x***)
    res = c.compound([c.setclientid(id=id, verifier=b'')])
    check(res)
    # (*xc*s), (*xd*t)
    res = c.compound([c.setclientid(id=id, verifier=b'')])
    check(res)
    
def testCallbackInfoUpdate(t, env):
    """A probable callback information update and records
       an unconfirmed { v, x, c, k, t } and leaves the
       confirmed { v, x, c, l, s } in place, such that t != s.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4a
    """
    c1 = env.c1
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())

    # confirmed { v, x, c, l, s }
    (cclientid, cconfirm) = c1.init_connection(clid, verifier=c1.verifier)

    # request { v, x, c, k, s } --> unconfirmed { v, x, c, k, t }
    ops = [c1.setclientid(clid, verifier=c1.verifier)]
    res = c1.compound(ops)
    check(res)

    tclientid = res.resarray[0].switch.switch.clientid
    tconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # (t != s)
    if tconfirm == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        t.fail("Got clientid confirm verifier with all zero!")

    if cclientid != tclientid:
        t.fail("Return a different clientID for callback information updating!")

    if tconfirm == cconfirm:
        t.fail("Return a same confirm for callback information updating!")

def testConfirmedDiffVerifier(t, env):
    """The server has previously recorded a confirmed { u, x, c, l, s }
       record such that v != u, l may or may not equal k, and has not
       recorded any unconfirmed { *, x, *, *, * } record for x.  The
       server records an unconfirmed { v, x, d, k, t } (d != c, t != s).

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4b
    """
    c1 = env.c1
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())

    # confirmed { u, x, c, l, s }
    (cclientid, cconfirm) = c1.init_connection(clid, verifier=c1.verifier)

    # request { v, x, c, k, s } --> unconfirmed { v, x, d, k, t }
    ops = [c1.setclientid(clid, verifier=b"diff")]
    res = c1.compound(ops)
    check(res)

    tclientid = res.resarray[0].switch.switch.clientid
    tconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # (d != c, t != s)
    if tconfirm == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        t.fail("Got clientid confirm verifier with all zero!")

    if cclientid == tclientid:
        t.fail("Return a same clientID for different verifier!")

    if tconfirm == cconfirm:
        t.fail("Return a same confirm for different verifier!")

def testConfUnConfDiffVerifier1(t, env):
    """The server has previously recorded a confirmed { u, x, c, l, s }
       record such that v != u, l may or may not equal k, and recorded an
       unconfirmed { w, x, d, m, t } record such that c != d, t != s, m
       may or may not equal k, m may or may not equal l, and k may or may
       not equal l.  Whether w == v or w != v makes no difference.  The
       server simply removes the unconfirmed { w, x, d, m, t } record and
       replaces it with an unconfirmed { v, x, e, k, r } record, such
       that e != d, e != c, r != t, r != s.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4c
    """
    c1 = env.c1
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())

    # confirmed { u, x, c, l, s }
    (cclientid, cconfirm) = c1.init_connection(clid, verifier=c1.verifier)

    # unconfirmed { w, x, d, m, t }
    ops = [c1.setclientid(clid, verifier=b"unconf")]
    res = c1.compound(ops)
    check(res)

    uclientid = res.resarray[0].switch.switch.clientid
    uconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # request { v, x, c, k, s } --> unconfirmed { v, x, e, k, r }
    # (v == w)
    ops = [c1.setclientid(clid, verifier=b"unconf")]
    res = c1.compound(ops)
    check(res)

    tclientid = res.resarray[0].switch.switch.clientid
    tconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # removes the unconfirmed { w, x, d, m, t }
    ops = [op.setclientid_confirm(uclientid, uconfirm)]
    res = c1.compound(ops)
    check(res, NFS4ERR_STALE_CLIENTID)

    # (e != d, e != c, r != t, r != s)
    if tconfirm == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        t.fail("Got clientid confirm verifier with all zero!")

    if cclientid == tclientid or uclientid == tclientid:
        t.fail("Return a same clientID for different verifier!")

    if tconfirm == cconfirm or tconfirm == uconfirm:
        t.fail("Return a same confirm for different verifier!")

def testConfUnConfDiffVerifier2(t, env):
    """Whether w == v or w != v makes no difference.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4d
    """
    c1 = env.c1
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())

    # confirmed { u, x, c, l, s }
    (cclientid, cconfirm) = c1.init_connection(clid, verifier=c1.verifier)

    # unconfirmed { w, x, d, m, t }
    ops = [c1.setclientid(clid, verifier=b"unconf")]
    res = c1.compound(ops)
    check(res)

    uclientid = res.resarray[0].switch.switch.clientid
    uconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # request { v, x, c, k, s } --> unconfirmed { v, x, e, k, r }
    # (v != w)
    ops = [c1.setclientid(clid, verifier=b"testconf")]
    res = c1.compound(ops)
    check(res)

    tclientid = res.resarray[0].switch.switch.clientid
    tconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # removes the unconfirmed { w, x, d, m, t }
    ops = [op.setclientid_confirm(uclientid, uconfirm)]
    res = c1.compound(ops)
    check(res, NFS4ERR_STALE_CLIENTID)

    # (e != d, e != c, r != t, r != s)
    if tconfirm == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        t.fail("Got clientid confirm verifier with all zero!")

    if cclientid == tclientid or uclientid == tclientid:
        t.fail("Return a same clientID for different verifier!")

    if tconfirm == cconfirm or tconfirm == uconfirm:
        t.fail("Return a same confirm for different verifier!")

def testUnConfReplaced(t, env):
    """The server has no confirmed { *, x, *, *, * } for x.  It may or
       may not have recorded an unconfirmed { u, x, c, l, s }, where l
       may or may not equal k, and u may or may not equal v.  Any
       unconfirmed record { u, x, c, l, * }, regardless of whether u == v
       or l == k, is replaced with an unconfirmed record { v, x, d, k, t}
       where d != c, t != s.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID4e
    """
    c1 = env.c1
    clid = b"Clid_for_%s_pid=%i" % (t.word(), os.getpid())

    # unconfirmed { w, x, d, m, t }
    ops = [c1.setclientid(clid, verifier=b"unconf")]
    res = c1.compound(ops)
    check(res)

    uclientid = res.resarray[0].switch.switch.clientid
    uconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # request { v, x, c, k, s } --> unconfirmed { v, x, d, k, t }
    ops = [c1.setclientid(clid, verifier=b"diff")]
    res = c1.compound(ops)
    check(res)

    tclientid = res.resarray[0].switch.switch.clientid
    tconfirm = res.resarray[0].switch.switch.setclientid_confirm

    # removes the unconfirmed { w, x, d, m, t }
    ops = [op.setclientid_confirm(uclientid, uconfirm)]
    res = c1.compound(ops)
    check(res, NFS4ERR_STALE_CLIENTID)

    # (d != c, t != s)
    if tconfirm == b'\x00\x00\x00\x00\x00\x00\x00\x00':
        t.fail("Got clientid confirm verifier with all zero!")

    if uclientid == tclientid:
        t.fail("Return a same clientID for different verifier!")

    if tconfirm == uconfirm:
        t.fail("Return a same confirm for different verifier!")

def testLotsOfClients(t, env):
    """SETCLIENTID called multiple times

    FLAGS: setclientid setclientidconfirm all
    DEPEND: INIT MKFILE
    CODE: CID5
    """
    c = env.c1
    basedir = c.homedir + [t.word()]
    res = c.create_obj(basedir)
    check(res)
    idlist = [b"Clientid%i_for_%s_pid%i" % (x, t.word(), os.getpid()) \
              for x in range(1024)]
    for id in idlist:
        c.init_connection(id)
        c.create_confirm(t.word(), basedir + [id])

def testNoConfirm(t, env):
    """SETCLIENTID - create a stale clientid, and use it.

    FLAGS: setclientid all
    DEPEND: INIT
    CODE: CID6
    """
    c = env.c1
    id = b"Clientid_for_%s_pid=%i" % (t.word(), os.getpid())
    res = c.compound([c.setclientid(id)])
    check(res)
    res = c.compound([c.setclientid(id, b'')])
    check(res)
    c.clientid = res.resarray[0].switch.switch.clientid
    ops = c.use_obj(c.homedir)
    ops += [c.open(t.word(), t.word(), OPEN4_CREATE)]
    res = c.compound(ops)
    check(res, [NFS4ERR_STALE_CLIENTID, NFS4ERR_EXPIRED],
          "OPEN using clientid that was never confirmed")
