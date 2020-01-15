from xdrdef.nfs4_const import *
from nfs4lib import list2bitmap
from .environment import check
import nfs_ops
op = nfs_ops.NFS4ops()

def testReference(t, env):
    """FSLOCATION test of referral node

    This assumes option --usespecial was set to point to correct path

    FLAGS: fslocations
    CODE: FSLOC1
    """
    c = env.c1
    path = env.opts.usespecial
    ops = [op.putrootfh(), op.getfh()]
    for comp in path:
        ops += [op.lookup(comp), op.getfh()]
    res = c.compound(ops)
    check(res, NFS4ERR_MOVED, "GETFH of path indicated by --usespecial")
    locs = c.do_getattr(FATTR4_FS_LOCATIONS, path)
    print("After NFS4ERR_MOVED, GETATTR(fs_locations) = %s" % locs)

def testReference2(t, env):
    """FSLOCATION test of referral node

    This assumes option --usespecial was set to point to correct path

    FLAGS: fslocations
    CODE: FSLOC2
    """
    c = env.c1
    path = env.opts.usespecial
    locs = c.do_getattr(FATTR4_FS_LOCATIONS, path)
    print("After NFS4ERR_MOVED, GETATTR(fs_locations) = %s" % locs)

def testReference3(t, env):
    """FSLOCATION test of referral node

    This assumes option --usespecial was set to point to correct path

    FLAGS: fslocations
    CODE: FSLOC3
    """
    c = env.c1
    path = env.opts.usespecial
    locs = c.do_getattr(FATTR4_FS_LOCATIONS, c.homedir)
    print("After NFS4ERR_MOVED, GETATTR(fs_locations) = %s" % locs)

def testAttr1a(t, env):
    """GETATTR with attributes should return _MOVED

    FLAGS: fslocations
    CODE: FSLOC4a
    """
    c = env.c1
    path = env.opts.usespecial
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_FSID]
    ops = c.use_obj(path)
    ops += [c.getattr(attrlist)]
    res = c.compound(ops)
    check(res, NFS4ERR_MOVED, "GETATTR w/o FSLOC or RDATTR_ERROR")

def testAttr1b(t, env):
    """READDIR with attributes should return _MOVED

    FLAGS: fslocations
    CODE: FSLOC4b
    """
    c = env.c1
    c.init_connection()
    path = env.opts.usespecial[:-1]
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_FSID]
    ops = c.use_obj(path)
    ops += [op.readdir(0, b'', 4096, 4096, list2bitmap(attrlist))]
    res = c.compound(ops)
    check(res, NFS4ERR_MOVED, "READDIR w/o FSLOC or RDATTR_ERROR")

def testAttr2a(t, env):
    """GETATTR with no FSLOC but with RDATTR_ERROR should return _MOVED

    FLAGS: fslocations
    CODE: FSLOC5a
    """
    c = env.c1
    path = env.opts.usespecial
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_RDATTR_ERROR, FATTR4_FSID]
    ops = c.use_obj(path)
    ops += [c.getattr(attrlist)]
    res = c.compound(ops)
    check(res, NFS4ERR_MOVED, "GETATTR w/o FSLOC but with RDATTR_ERROR")

def testAttr2b(t, env):
    """READDIR with no FSLOC but with RDATTR_ERROR should put _MOVED in
    _RDATTR_ERROR and return what it can

    FLAGS: fslocations
    CODE: FSLOC5b
    """
    c = env.c1
    c.init_connection()
    path = env.opts.usespecial[:-1]
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_RDATTR_ERROR, FATTR4_FSID]
    entries = c.do_readdir(path, attr_request=attrlist)
    moved = [e for e in entries if e.attrdict[FATTR4_RDATTR_ERROR] == NFS4ERR_MOVED]
    print("RDATTR==MOVED for:", [e.name for e in moved])
    for e in moved:
        if len(e.attrdict) != 2:
            print(e.attrdict)
            t.fail("Expected 2 attrs returned for file %s, got %i" % (e.name, len(e.attrdict)))
        
def testAttr3a(t, env):
    """GETATTR with restricted attrs but no FSLOC should work

    FLAGS: fslocations
    CODE: FSLOC6a
    """
    c = env.c1
    path = env.opts.usespecial
    attrlist = [FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_MOUNTED_ON_FILEID]
    ops = c.use_obj(path)
    ops += [c.getattr(attrlist)]
    res = c.compound(ops)
    check(res, msg = "GETATTR w/o FSLOC but only restricted attrs")

def testAttr3b(t, env):
    """READDIR with restricted attrs but no FSLOC should work

    FLAGS: fslocations
    CODE: FSLOC6b
    """
    c = env.c1
    c.init_connection()
    path = env.opts.usespecial[:-1]
    attrlist = [FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_MOUNTED_ON_FILEID]
    entries = c.do_readdir(path, attr_request=attrlist)
    moved = [e for e in entries if e.name == env.opts.usespecial[-1]][0]
    if len(moved.attrdict) != 3:
        print(moved.attrdict)
        t.fail("Expected 3 attrs returned for file %s, got %i" % (moved.name, len(moved.attrdict)))
        
def testAttr4a(t, env):
    """GETATTR with FSLOC and RDATTR_ERROR should return what can

    FLAGS: fslocations
    CODE: FSLOC7a
    """
    c = env.c1
    path = env.opts.usespecial
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_FS_LOCATIONS]
    d = c.do_getattrdict(path, attrlist)
    print(d)
    if len(d) != 3:
        t.fail("Expected 3 attrs returned, got %i" % len(d))

def testAttr4b(t, env):
    """READDIR with FSLOC and RDATTR_ERROR should put _MOVED in
    _RDATTR_ERROR and return what it can

    FLAGS: fslocations
    CODE: FSLOC7b
    """
    c = env.c1
    c.init_connection()
    path = env.opts.usespecial[:-1]
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_RDATTR_ERROR, FATTR4_FSID, FATTR4_FS_LOCATIONS]
    entries = c.do_readdir(path, attr_request=attrlist)
    moved = [e for e in entries if e.attrdict[FATTR4_RDATTR_ERROR] == NFS4ERR_MOVED]
    print("RDATTR==MOVED for:", [e.name for e in moved])
    for e in moved:
        if len(e.attrdict) != 3:
            print(e.attrdict)
            t.fail("Expected 3 attrs returned for file %s, got %i" % (e.name, len(e.attrdict)))
        
def testAttr5a(t, env):
    """GETATTR with FSLOC but no RDATTR_ERROR should return what can

    FLAGS: fslocations
    CODE: FSLOC8a
    """
    c = env.c1
    path = env.opts.usespecial
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_FSID, FATTR4_FS_LOCATIONS]
    d = c.do_getattrdict(path, attrlist)
    print(d)
    if len(d) != 2:
        t.fail("Expected 3 attrs returned, got %i" % len(d))

def testAttr5b(t, env):
    """READDIR with FSLOC but no RDATTR_ERROR should put _MOVED in
    _RDATTR_ERROR and return what it can

    FLAGS: fslocations
    CODE: FSLOC8b
    """
    c = env.c1
    c.init_connection()
    path = env.opts.usespecial[:-1]
    attrlist = [FATTR4_SIZE, FATTR4_FILEHANDLE, FATTR4_FSID, FATTR4_FS_LOCATIONS]
    entries = c.do_readdir(path, attr_request=attrlist)
    moved = [e for e in entries if e.name == env.opts.usespecial[-1]][0]
    if len(moved.attrdict) != 2:
        print(moved.attrdict)
        t.fail("Expected 2 attrs returned for file %s, got %i" % (moved.name, len(moved.attrdict)))
        
