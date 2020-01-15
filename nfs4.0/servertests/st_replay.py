from xdrdef.nfs4_const import *
from .environment import check
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()

def _replay(env, c, ops, error=NFS4_OK):
    # Can send in an error list, but replays must return same error as orig
    if type(error) is list:
        check_funct = check
    else:
        check_funct = check
    res = c.compound(ops)
    check_funct(res, error, "Call to be replayed")
    error = res.status
    xid = c.xid
    orig_funct = c.get_new_xid
    try:
        c.get_new_xid = lambda : xid

        # note: this is really cheesy: we happen to know the current
        # Linux server implementation will drop a replay if it comes
        # "too quickly" (<.02 seconds).
        # Also, note no 4.0 client should really be replaying like this
        # without reconnecting first, so this test is really acting like
        # a buggy client and a server would probably be in its rights to
        # ignore these replays or return unexpected errors:

        env.sleep(.3)
        res = c.compound(ops)
        check(res, error, "Replay the first time")
        env.sleep(.3)
        res = c.compound(ops)
        check(res, error, "Replay the second time")
    finally:
        c.get_new_xid = orig_funct

def testOpen(t, env):
    """REPLAY: Send three OPEN calls with the same XID, SEQID, check DRC

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY1
    """
    c = env.c1
    c.init_connection()
    ops = c.use_obj(c.homedir)
    ops += [c.open(t.word(), type=OPEN4_CREATE), op.getfh()]
    _replay(env, c, ops)
    # Note that seqid is now off on this and other replay tests


def testReplayState1(t, env):
    """REPLAY an erroneous OPEN of a nonexistant file

    FLAGS: replay all
    DEPEND: MKDIR INIT
    CODE: RPLY2
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir + [t.word()])
    ops += [c.open(t.word(), b'vapor'), op.getfh()]
    _replay(env, c, ops, NFS4ERR_NOENT)
    
def testReplayState2(t, env):
    """REPLAY an erroneous OPEN of a dir

    FLAGS: replay all
    DEPEND: MKDIR INIT
    CODE: RPLY3
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir)
    ops += [c.open(t.word()), op.getfh()]
    _replay(env, c, ops, NFS4ERR_ISDIR)

def testReplayNonState(t, env):
    """REPLAY an erroneous LOOKUP

    FLAGS: replay all
    DEPEND: MKDIR
    CODE: RPLY4
    """
    c = env.c1
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir + [t.word(), b'vapor'])
    _replay(env, c, ops, NFS4ERR_NOENT)

def testLock(t, env):
    """REPLAY a LOCK command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY5
    """
    c = env.c1
    c.init_connection()
    # Create a file and partially lock it
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    # Create and replay LOCK ops
    ops = c.use_obj(fh)
    lock_owner = exist_lock_owner4(res.lockid, 1)
    locker = locker4(FALSE, lock_owner=lock_owner)
    ops += [op.lock(WRITE_LT, FALSE, 0, 10, locker)]
    _replay(env, c, ops)
    
def testLockDenied(t, env):
    """REPLAY a LOCK command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY6
    """
    c = env.c1
    c.init_connection()
    # Create a file and lock it
    fh, stateid = c.create_confirm(t.word())
    res1 = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res1, msg="Locking file %s for first owner" % t.word())
    res2 = c.lock_file(t.word(), fh, stateid, 0, 10)
    check(res2, msg="Locking file %s for second owner" % t.word())
    # Create and replay LOCK ops
    ops = c.use_obj(fh)
    lock_owner = exist_lock_owner4(res1.lockid, 1)
    locker = locker4(FALSE, lock_owner=lock_owner)
    ops += [op.lock(WRITE_LT, FALSE, 0, 10, locker)]
    _replay(env, c, ops, NFS4ERR_DENIED)
    
def testUnlock(t, env):
    """REPLAY a LOCKU command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY7
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    ops = c.use_obj(fh)
    ops += [op.locku(READ_LT, 1, res.lockid, 0, 0xffffffffffffffff)]
    _replay(env, c, ops)

def testUnlockWait(t, env):
    """REPLAY a LOCKU command after lease has expired

    FLAGS: replay all timed
    DEPEND: MKFILE
    CODE: RPLY8
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    sleeptime = c.getLeaseTime() * 2
    env.sleep(sleeptime)
    ops = c.use_obj(fh)
    ops += [op.locku(READ_LT, 1, res.lockid, 0, 0xffffffffffffffff)]
    _replay(env, c, ops, [NFS4_OK, NFS4ERR_EXPIRED])

def testClose(t, env):
    """REPLAY a CLOSE command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY9
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word()), stateid)]
    _replay(env, c, ops)
    
def testCloseWait(t, env):
    """REPLAY a CLOSE command after lease has expired

    FLAGS: replay all timed
    DEPEND: MKFILE
    CODE: RPLY10
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    sleeptime = c.getLeaseTime() * 2
    env.sleep(sleeptime)
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word()), stateid)]
    _replay(env, c, ops, [NFS4_OK, NFS4ERR_EXPIRED])
    
def testCloseFail(t, env):
    """REPLAY a CLOSE command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY11
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word())+1, stateid)]
    _replay(env, c, ops, NFS4ERR_BAD_SEQID)
    
def testOpenConfirm(t, env):
    """REPLAY an OPEN_CONFIRM command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY12
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    rflags = res.resarray[-2].switch.switch.rflags
    if not rflags & OPEN4_RESULT_CONFIRM:
        t.pass_warn("OPEN did not require CONFIRM")
    ops = c.use_obj(fh)
    ops += [op.open_confirm(stateid, c.get_seqid(t.word()))]
    _replay(env, c, ops)
    
def testOpenConfirmFail(t, env):
    """REPLAY an OPEN_CONFIRM command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY13
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    rflags = res.resarray[-2].switch.switch.rflags
    if not rflags & OPEN4_RESULT_CONFIRM:
        t.pass_warn("OPEN did not require CONFIRM")
    ops = c.use_obj(fh)
    ops += [op.open_confirm(stateid, c.get_seqid(t.word())+1)]
    _replay(env, c, ops, NFS4ERR_BAD_SEQID)

def testMkdirReplay(t, env):
    """REPLAY a succesful directory CREATE

    FLAGS: replay all
    DEPEND: MKDIR
    CODE: RPLY14
    """
    c = env.c1
    c.init_connection()
    ops = c.go_home() + [op.create(createtype4(NF4DIR), t.word(), {})]
    _replay(env, c, ops)
