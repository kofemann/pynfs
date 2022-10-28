from xdrdef.nfs4_const import *
from .environment import check, makeBadID, makeBadIDganesha, makeStaleId
import rpc.rpc as rpc

def _compare(t, res, expect, eof=True):
    def shorten(str):
        if len(str)<64:
            return repr(str)
        else:
            return "%s..." % repr(str[0:64])
    count = len(res.data)
    if res.data != expect[:count]:
        t.fail("READ returned '%s', expected '%s'" % (res.data, expect))
    if count < len(expect):
        if res.eof:
             t.fail("READ returned EOF after getting %s, expected %s" %
                   (shorten(res.data), shorten(expect)))
        else:
             t.pass_warn("READ returned %i characters, expected %i" %
                        (count, len(expect)))
    if res.eof != eof:
        if eof:
            t.fail("READ to file end returned without EOF set")
        else:
            t.fail("READ unexpectedly returned EOF")

##########################################

def testSimpleRead(t, env):
    """READ from regular file with stateid=zeros

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD1
    """
    c = env.c1
    res = c.read_file(env.opts.usefile)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, env.filedata, True)

def testStateidOnes(t, env):
    """READ with offset=2, count=2, stateid=ones

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD2
    """
    c = env.c1
    res = c.read_file(env.opts.usefile, 2, 2, env.stateid1)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, env.filedata[2:4], False)

def testWithOpen(t, env):
    """READ with offset=5, count=1000, stateid from OPEN

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD3
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.open_confirm(t.word(), env.opts.usefile)
    res = c.read_file(fh, 5, 1000, stateid)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, env.filedata[5:1005], True)
    
def testLargeCount(t, env):
    """READ a large dataset

    FLAGS: ganesha
    DEPEND: MKFILE
    CODE: RD4
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), attrs={FATTR4_SIZE: 10000000,
                                                  FATTR4_MODE: 0o644})
    res = c.read_file(fh, 0, 9000000, stateid)
    check(res, msg="Reading file %s" % t.word())
    _compare(t, res, b'\x00'*9000000, False)

def testLargeOffset(t, env):
    """READ with offset outside file

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD5
    """
    c = env.c1
    res = c.read_file(env.opts.usefile, 1000, 10)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, b'', True)

def testVeryLargeOffset(t, env):
    """READ with offset far outside file

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD5a
    """
    c = env.c1
    res = c.read_file(env.opts.usefile, 0x7ffffffffffffffc, 10)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, b'', True)

def testZeroCount(t, env):
    """READ with count=0

    FLAGS: read all
    DEPEND: LOOKFILE
    CODE: RD6
    """
    c = env.c1
    res = c.read_file(env.opts.usefile, 5, 0)
    check(res, msg="Reading file /%s" % b'/'.join(env.opts.usefile))
    _compare(t, res, b'', False)

def testDir(t, env):
    """READ with non-file objects

    FLAGS: read dir all 
    DEPEND: LOOKDIR
    CODE: RD7d
    """
    c = env.c1
    res = c.read_file(env.opts.usedir)
    check(res, NFS4ERR_ISDIR, "Read of a directory")
    
def testLink(t, env):
    """READ with non-file objects

    FLAGS: read symlink all 
    DEPEND: LOOKLINK
    CODE: RD7a
    """
    c = env.c1
    res = c.read_file(env.opts.uselink)
    check(res, [NFS4ERR_INVAL, NFS4ERR_SYMLINK], "Read of a non-file object")

def testBlock(t, env):
    """READ with non-file objects

    FLAGS: read block all 
    DEPEND: LOOKBLK
    CODE: RD7b
    """
    c = env.c1
    res = c.read_file(env.opts.useblock)
    check(res, NFS4ERR_INVAL, "Read of a non-file object")

def testChar(t, env):
    """READ with non-file objects

    FLAGS: read char all 
    DEPEND: LOOKCHAR
    CODE: RD7c
    """
    c = env.c1
    res = c.read_file(env.opts.usechar)
    check(res, NFS4ERR_INVAL, "Read of a non-file object")

def testFifo(t, env):
    """READ with non-file objects

    FLAGS: read fifo all 
    DEPEND: LOOKFIFO
    CODE: RD7f
    """
    c = env.c1
    res = c.read_file(env.opts.usefifo)
    check(res, NFS4ERR_INVAL, "Read of a non-file object")

def testSocket(t, env):
    """READ with non-file objects

    FLAGS: read socket all 
    DEPEND: LOOKSOCK
    CODE: RD7s
    """
    c = env.c1
    res = c.read_file(env.opts.usesocket)
    check(res, NFS4ERR_INVAL, "Read of a non-file object")

def testNoFh(t, env):
    """READ without (cfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: read emptyfh all 
    CODE: RD8
    """
    c = env.c1
    res = c.read_file(None)
    check(res, NFS4ERR_NOFILEHANDLE, "READ with no <cfh>")

# RD9 requires a server specific manipulation of the stateid
#     each server will have it's own implementation, there is
#     no general version.
def testBadStateidGanesha(t, env):
    """READ with bad stateid should return NFS4ERR_BAD_STATEID

    FLAGS: ganesha
    DEPEND: MKFILE
    CODE: RD9g
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.read_file(fh, stateid=makeBadIDganesha(stateid))
    check(res, NFS4ERR_BAD_STATEID, "READ with bad stateid")

def testStaleStateid(t, env):
    """READ with stale stateid should return NFS4ERR_STALE_STATEID

    FLAGS: read staleid all
    DEPEND: MKFILE
    CODE: RD10
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.read_file(fh, stateid=makeStaleId(stateid))
    check(res, NFS4ERR_STALE_STATEID, "READ with stale stateid")

def testOldStateid(t, env):
    """READ with old stateid should return NFS4ERR_OLD_STATEID

    FLAGS: read oldid all
    DEPEND: MKFILE
    CODE: RD11
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res, msg="Creating file %s" % t.word())
    oldstateid = res.resarray[-2].switch.switch.stateid
    fh, stateid = c.confirm(t.word(), res)
    res = c.read_file(fh, stateid=oldstateid)
    check(res, NFS4ERR_OLD_STATEID, "READ with old stateid")

# Off by default just because it's a bit hackish and assumes auth_sys:
def testStolenStateid(t, env):
    """READ with incorrect permissions and somebody else's stateid

    FLAGS: read
    DEPEND: MKFILE
    CODE: RD12
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word(), attrs={FATTR4_MODE: 0o600})
    fh, stateid = c.confirm(t.word(), res)
    security=c.security
    c.security=rpc.SecAuthSys(0, "whatever", 3912, 2422, [])
    res = c.read_file(fh, stateid=stateid)
    c.security=security
    check(res, [NFS4ERR_ACCESS, NFS4ERR_PERM], "READ with stolen stateid")

def testLargeMultipleRead(t, env):
    """READ a large dataset with multiple reads

    FLAGS: read
    DEPEND: MKFILE
    CODE: RD13
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), attrs={FATTR4_SIZE: 10000000,
                                                  FATTR4_MODE: 0o644})

    op_count = 2
    read_size = 384 * 1024

    ops = c.use_obj(fh)
    for _ in range(op_count):
        ops.append(c.read(0, read_size, stateid))

    res = c.compound(ops)
    if res.status != NFS4_OK:
        t.fail("READ failed with %s" % res.status)

    for x in range(op_count):
        res.eof = res.resarray[-1 - x].switch.switch.eof
        res.data = res.resarray[-1 - x].switch.switch.data
        check(res, msg="Reading file %s" % t.word())
        _compare(t, res, b'\x00'*read_size, False)
