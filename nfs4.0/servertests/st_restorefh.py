from xdrdef.nfs4_const import *
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

def _try_sequence(t, c, path):
    """Try saving path, looking elsewhere, then restoring path"""
    ops = c.use_obj(path) + [op.getfh(), op.savefh()]
    ops += [op.putrootfh()]
    ops += [op.restorefh(), op.getfh()]
    res = c.compound(ops)
    check(res)

    fh1 = res.resarray[-5].switch.switch.object
    fh2 = res.resarray[-1].switch.switch.object
    if fh1 != fh2:
        t.fail("restored FH does not match saved FH")
    
def testValidFile(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh file all
    DEPEND: LOOKFILE
    CODE: SVFH2r
    """
    _try_sequence(t, env.c1, env.opts.usefile)
    
def testValidDir(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh dir all
    DEPEND: LOOKDIR
    CODE: SVFH2d
    """
    _try_sequence(t, env.c1, env.opts.usedir)

def testValidFifo(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh fifo all
    DEPEND: LOOKFIFO
    CODE: SVFH2f
    """
    _try_sequence(t, env.c1, env.opts.usefifo)

def testValidLink(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh symlink all
    DEPEND: LOOKLINK
    CODE: SVFH2a
    """
    _try_sequence(t, env.c1, env.opts.uselink)

def testValidBlock(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh block all
    DEPEND: LOOKBLK
    CODE: SVFH2b
    """
    _try_sequence(t, env.c1, env.opts.useblock)

def testValidChar(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh char all
    DEPEND: LOOKCHAR
    CODE: SVFH2c
    """
    _try_sequence(t, env.c1, env.opts.usechar)

def testValidSocket(t, env):
    """RESTOREFH simple save and restore

    FLAGS: savefh restorefh socket all
    DEPEND: LOOKSOCK
    CODE: SVFH2s
    """
    _try_sequence(t, env.c1, env.opts.usesocket)

def testNoFh1(t, env):
    """RESTOREFH without (sfh) or (cfh) should return NFS4ERR_RESTOREFH

    FLAGS: restorefh emptyfh all
    CODE: RSFH1
    """
    c = env.c1
    res = c.compound([op.restorefh()])
    check(res, NFS4ERR_RESTOREFH, "RESTOREFH with no <cfh>")

def testNoFh2(t, env):
    """RESTOREFH without (sfh) should return NFS4ERR_RESTOREFH

    FLAGS: restorefh emptyfh all
    CODE: RSFH2
    """
    c = env.c1
    res = c.compound([op.putrootfh(), op.restorefh()])
    check(res, NFS4ERR_RESTOREFH, "RESTOREFH with no <cfh>")
