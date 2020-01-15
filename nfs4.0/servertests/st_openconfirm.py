from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import stateid4
from .environment import check, makeStaleId
import nfs_ops
op = nfs_ops.NFS4ops()

def _confirm(t, c, file, stateid):
    ops = c.use_obj(file)
    ops += [op.open_confirm(stateid, c.get_seqid(t.word()))]
    res = c.compound(ops)
    c.advance_seqid(t.word(), res)
    return res

def testConfirmCreate(t, env):
    """OPEN_CONFIRM done twice in a row should return NFS4ERR_BAD_STATEID

    FLAGS: openconfirm all
    DEPEND: MKFILE
    CODE: OPCF1
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    # Now confirm again
    res = _confirm(t, c, fh, stateid)
    check(res, NFS4ERR_BAD_STATEID, "OPEN_CONFIRM done twice in a row")

def testNoFh(t, env):
    """OPENCONFIRM  should fail with NFS4ERR_NOFILEHANDLE if no (cfh)

    FLAGS: openconfirm emptyfh all
    CODE: OPCF2
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    stateid = res.resarray[-2].switch.switch.stateid
    res = _confirm(t, c, None, stateid)
    check(res, NFS4ERR_NOFILEHANDLE, "OPEN_CONFIRM with no <cfh>")

# retiring test codes, please don't reuse:
# OPCF3d
# OPCF3a
# OPCF3f
# OPCF3b
# OPCF3c
# OPCF3s

def testBadSeqid(t, env):
    """OPEN_CONFIRM with a bad seqid should return NFS4ERR_BAD_SEQID

    FLAGS: openconfirm seqid all
    CODE: OPCF4
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    stateid = res.resarray[-2].switch.switch.stateid
    fh = res.resarray[-1].switch.switch.object
    ops = [op.putfh(fh), op.open_confirm(stateid, 50)]
    res = c.compound(ops)
    check(res, NFS4ERR_BAD_SEQID, "OPEN_CONFIRM with a bad seqid=50")

def testBadStateid(t, env):
    """OPEN_CONFIRM with a bad state should return NFS4ERR_BAD_STATEID

    FLAGS: openconfirm badid all
    CODE: OPCF5
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    fh = res.resarray[-1].switch.switch.object
    res = _confirm(t, c, fh, stateid4(0, b''))
    check(res, NFS4ERR_BAD_STATEID, "OPEN_CONFIRM with a bad state")

def testStaleStateid(t, env):
    """OPEN_CONFIRM with a stale state should return NFS4ERR_STALE_STATEID

    FLAGS: openconfirm staleid all
    CODE: OPCF6
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    stateid = res.resarray[-2].switch.switch.stateid
    fh = res.resarray[-1].switch.switch.object
    res = _confirm(t, c, fh, makeStaleId(stateid))
    check(res, NFS4ERR_STALE_STATEID, "OPEN_CONFIRM with a stale state")

 # FRED - old id test
 
