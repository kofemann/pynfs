from xdrdef.nfs4_const import *
from .environment import check, get_invalid_utf8strings
import nfs_ops
op = nfs_ops.NFS4ops()

def testDir(t, env):
    """LOOKUPP with directory (cfh)

    FLAGS: lookupp all
    DEPEND: MKDIR
    CODE: LOOKP1
    """
    c = env.c1
    res = c.create_obj(c.homedir + [t.word()])
    check(res)
    ops = c.use_obj(c.homedir)
    ops += [op.getfh(), op.lookup(t.word()), op.lookupp(), op.getfh()]
    res = c.compound(ops)
    check(res)
    fh1 = res.resarray[-4].switch.switch.object
    fh2 = res.resarray[-1].switch.switch.object
    if fh1 != fh2:
        t.fail("LOOKUPP FH does not match orig FH")

def testFile(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp file all
    DEPEND: LOOKFILE
    CODE: LOOKP2r
    """
    c = env.c1
    ops = c.use_obj(env.opts.usefile) + [op.lookupp()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")
    
def testFifo(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp fifo all
    DEPEND: LOOKFIFO
    CODE: LOOKP2f
    """
    c = env.c1
    ops = c.use_obj(env.opts.usefifo) + [op.lookupp()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")
    
def testLink(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp symlink all
    DEPEND: LOOKLINK
    CODE: LOOKP2a
    """
    c = env.c1
    ops = c.use_obj(env.opts.uselink) + [op.lookupp()]
    res = c.compound(ops)
    check(res, [NFS4ERR_NOTDIR, NFS4ERR_SYMLINK],
                "LOOKUPP with non-dir <cfh>")
    
def testBlock(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp block all
    DEPEND: LOOKBLK
    CODE: LOOKP2b
    """
    c = env.c1
    ops = c.use_obj(env.opts.useblock) + [op.lookupp()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")
    
def testChar(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp char all
    DEPEND: LOOKCHAR
    CODE: LOOKP2c
    """
    c = env.c1
    ops = c.use_obj(env.opts.usechar) + [op.lookupp()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")
    
def testSock(t, env):
    """LOOKUPP with non-dir (cfh)

    FLAGS: lookupp socket all
    DEPEND: LOOKSOCK
    CODE: LOOKP2s
    """
    c = env.c1
    ops = c.use_obj(env.opts.usesocket) + [op.lookupp()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOTDIR, "LOOKUPP with non-dir <cfh>")

def testAtRoot(t, env):
    """LOOKUPP with (cfh) at root should return NFS4ERR_NOENT

    FLAGS: lookupp all
    CODE: LOOKP3
    """
    c = env.c1
    res = c.compound([op.putrootfh(), op.lookupp()])
    check(res, NFS4ERR_NOENT, "LOOKUPP at root")

def testNoFh(t, env):
    """LOOKUPP with no (cfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: lookupp all
    CODE: LOOKP4
    """
    c = env.c1
    res = c.compound([op.lookupp()])
    check(res, NFS4ERR_NOFILEHANDLE, "LOOKUPP at root")

def testXdev(t, env):
    """LOOKUPP with dir on different fs

    FLAGS: special
    DEPEND: 
    CODE: LOOKP5
    """
    c = env.c1
    ops = [op.putrootfh(), op.getfh(),
           op.lookup(env.opts.usespecial[-1]), op.lookupp(), op.getfh()]
    res = c.compound(ops)
    check(res)
    fh1 = res.resarray[1].switch.switch.object
    fh2 = res.resarray[-1].switch.switch.object
    if fh1 != fh2:
        t.fail("file handles not equal")

def testXdevHome(t, env):
    """LOOKUPP with dir on different fs

    FLAGS: special ganesha
    DEPEND: 
    CODE: LOOKP6
    """
    c = env.c1
    ops = [op.putrootfh(), op.getfh()]
    ops += c.lookup_path(c.homedir)
    ops += c.lookupp_path(c.homedir)
    ops += [op.getfh()]
    res = c.compound(ops)
    check(res)
    fh1 = res.resarray[1].switch.switch.object
    fh2 = res.resarray[-1].switch.switch.object
    if fh1 != fh2:
        t.fail("file handles not equal")
