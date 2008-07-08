from nfs4_const import *
from environment import check, fail, maketree, rename_obj, get_invalid_utf8strings, create_obj, create_confirm, link, use_obj, create_file
import nfs4_ops as op
from nfs4_type import *

def testValidDir(t, env):
    """RENAME : normal operation

    FLAGS: rename dir all
    CODE: RNM1d
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1', ['foo']], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of directory %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidFile(t, env):
    """RENAME : normal operation

    FLAGS: rename file all
    CODE: RNM1r
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1', 'foo'], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of file %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidLink(t, env):
    """RENAME : normal operation

    FLAGS: rename symlink all
    CODE: RNM1a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4LNK, linkdata=env.linkdata))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of symlink %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidBlock(t, env):
    """RENAME : normal operation

    FLAGS: rename block all
    CODE: RNM1b
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4BLK, devdata=specdata4(1, 2)))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of block device %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidChar(t, env):
    """RENAME : normal operation

    FLAGS: rename char all
    CODE: RNM1c
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4BLK, devdata=specdata4(1, 2)))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of character device %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidFifo(t, env):
    """RENAME : normal operation

    FLAGS: rename fifo all
    CODE: RNM1f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], NF4FIFO)
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of fifo %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testValidSocket(t, env):
    """RENAME : normal operation

    FLAGS: rename socket all
    CODE: RNM1s
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], NF4SOCK)
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of socket %s/dir1/foo to %s/dir2/bar" %
          (t.code, t.code))

def testSfhFile(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename file all
    CODE: RNM2r
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.usefile + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhLink(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_SYMLINK

    FLAGS: rename symlink all
    CODE: RNM2a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.uselink + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_SYMLINK, "RENAME with non-dir <sfh>")

def testSfhBlock(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename block all
    CODE: RNM2b
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.useblock + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhChar(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename char all
    CODE: RNM2c
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.usechar + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhFifo(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename fifo all
    CODE: RNM2f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.usefifo + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhSocket(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename socket all
    CODE: RNM2s
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = rename_obj(sess, env.opts.usesocket + [t.code], env.c1.homedir + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testCfhFile(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename file all
    CODE: RNM3r
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.usefile + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhLink(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_SYMLINK

    FLAGS: rename symlink all
    CODE: RNM3a
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.uselink + [t.code])
    check(res, NFS4ERR_SYMLINK, "RENAME with non-dir <cfh>")

def testCfhBlock(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename block all
    CODE: RNM3b
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.useblock + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhChar(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename char all
    CODE: RNM3c
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.usechar + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhFifo(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename fifo all
    CODE: RNM3f
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.usefifo + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhSocket(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename socket all
    CODE: RNM3s
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    res = create_obj(sess, [t.code])
    try:
        check(res)
    except:
        check(res, NFS4ERR_EXIST)
    res = rename_obj(sess, env.c1.homedir + [t.code], env.opts.usesocket + [t.code])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testNoSfh(t, env):
    """RENAME without (sfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: rename emptyfh all
    CODE: RNM4
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    ops = env.home + [op.rename(t.code, t.code)]
    res = sess.compound(ops)
    check(res, NFS4ERR_NOFILEHANDLE, "RENAME with no <sfh>")

# FRED - can't test No Cfh, with a Sfh

def testNonExistent(t, env):
    """RENAME on non-existing object should return NFS4ERR_NOENT

    FLAGS: rename all
    CODE: RNM5
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + ['foo'], basedir + ['bar'])
    check(res, NFS4ERR_NOENT, "RENAME on non-existing object %s/foo" % t.code)

def testZeroLengthOldname(t, env):
    """RENAME with zero length oldname should return NFS4ERR_INVAL

    FLAGS: rename all
    CODE: RNM6
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + [''], basedir + ['bar'])
    check(res, NFS4ERR_INVAL, "RENAME with zero length oldname")

def testZeroLengthNewname(t, env):
    """RENAME with zero length newname should return NFS4ERR_INVAL

    FLAGS: rename all
    CODE: RNM7
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + ['foo'], basedir + [''])
    check(res, NFS4ERR_INVAL, "RENAME with zero length newname")

def testBadutf8Oldname(t, env):
    """RENAME with non-UTF8 oldname should return NFS4ERR_INVAL

    FLAGS: rename utf8 all
    CODE: RNM8
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    res = create_obj(sess, basedir)
    check(res)
    for name in get_invalid_utf8strings():
        res = rename_obj(sess, basedir + [name], basedir + [t.code])
        check(res, NFS4ERR_INVAL, "RENAME with non-UTF8 oldname %s/%s" %
                                   (t.code, repr(name)[1:-1]))

def testBadutf8Newname(t, env):
    """RENAME with non-UTF8 newname should return NFS4ERR_INVAL

    FLAGS: rename utf8 all
    CODE: RNM9
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, [t.code]])
    for name in get_invalid_utf8strings():
        res = rename_obj(sess, basedir + [t.code], basedir + [name])
        check(res, NFS4ERR_INVAL, "RENAME with non-UTF8 newname %s/%s" %
                                   (t.code, repr(name)[1:-1]))

def testDotsOldname(t, env):
    """RENAME from nonexistant . or .. should return _NOENT/_BADNAME

    FLAGS: rename dots all
    CODE: RNM10
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, [t.code]])
    res = rename_obj(sess, basedir + ['.'], basedir + [t.code])
    check(res, NFS4ERR_BADNAME, "RENAME from nonexistant '.'",
          [NFS4ERR_NOENT])
    res = rename_obj(sess, basedir + ['..'], basedir + [t.code])
    check(res, NFS4ERR_BADNAME, "RENAME from nonexistant '..'",
          [NFS4ERR_NOENT])

def testDotsNewname(t, env):
    """RENAME into . or .. should return _BADNAME or NFS4_OK

    FLAGS: rename dots all
    CODE: RNM11
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, [t.code]])
    res = rename_obj(sess, basedir + [t.code], basedir + ['.'])
    check(res, NFS4ERR_BADNAME, "RENAME into '.'",
          [NFS4_OK])
    res = rename_obj(sess, basedir + ['..'], basedir + [t.code])
    check(res, NFS4ERR_BADNAME, "RENAME into '..'",
          [NFS4_OK])

def testDirToObj(t, env):
    """RENAME dir into existing nondir should return NFS4ERR_EXIST

    FLAGS: rename all
    CODE: RNM12
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir'], 'file'])
    res = rename_obj(sess, basedir + ['dir'], basedir + ['file'])
    check(res, NFS4ERR_EXIST, "RENAME dir into existing file")

def testDirToDir(t, env):
    """RENAME dir into existing, empty dir should retrun NFS4_OK

    FLAGS: rename all
    CODE: RNM13
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1', ['foo']], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1'], basedir + ['dir2'])
    check(res, msg="RENAME dir1 into existing, empty dir2")

def testFileToDir(t, env):
    """RENAME file into existing dir should return NFS4ERR_EXIST

    FLAGS: rename all
    CODE: RNM14
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir'], 'file'])
    res = rename_obj(sess, basedir + ['file'], basedir + ['dir'])
    check(res, NFS4ERR_EXIST, "RENAME file into existing dir")

def testFileToFile(t, env):
    """RENAME file into existing file should return NFS4_OK

    FLAGS: rename all
    CODE: RNM15
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, 'file1', 'file2'])
    res = rename_obj(sess, basedir + ['file1'], basedir + ['file2'])
    check(res, msg="RENAME file1 into existing file2")

def testDirToFullDir(t, env):
    """RENAME dir into existing, nonempty dir should return NFS4ERR_EXIST

    FLAGS: rename all
    CODE: RNM16
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, ['dir1'], ['dir2', ['foo']]])
    res = rename_obj(sess, basedir + ['dir1'], basedir + ['dir2'])
    check(res, NFS4ERR_EXIST, "RENAME dir1 into existing, nonempty dir2")

def testFileToFullDir(t, env):
    """RENAME file into existing, nonempty dir should return NFS4ERR_EXIST

    FLAGS: rename all
    CODE: RNM17
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    basedir = env.c1.homedir + [t.code]
    maketree(sess, [t.code, 'file', ['dir', ['foo']]])
    res = rename_obj(sess, basedir + ['file'], basedir + ['dir'])
    check(res, NFS4ERR_EXIST, "RENAME file into existing, nonempty dir")

def testSelfRenameDir(t, env):
    """RENAME that does nothing

    FLAGS: rename all
    CODE: RNM18
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    maketree(sess, [t.code])
    basedir = env.c1.homedir + [t.code]
    res = rename_obj(sess, basedir, basedir)
    check(res)
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of dir %s into itself should do nothing, "
               "but cinfo was changed" % t.code)

def testSelfRenameFile(t, env):
    """RENAME that does nothing

    FLAGS: rename all
    CODE: RNM19
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    fh, stateid = create_confirm(sess, t.code)
    basedir = env.c1.homedir + [t.code]
    res = rename_obj(sess, basedir, basedir)
    check(res)
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of file %s into itself should do nothing, "
               "but cinfo was changed" % t.code)


def testLinkRename(t, env):
    """RENAME of file into its hard link should do nothing

    FLAGS: rename all
    CODE: RNM20
    """
    c = env.c1.new_client(env.testname(t))
    sess = c.create_session()
    maketree(sess, [t.code, 'file'])
    basedir = env.c1.homedir + [t.code]
    res = link(sess, basedir + ['file'], basedir + ['link'])
    check(res)
    res = rename_obj(sess, basedir + ['file'], basedir + ['link'])
    check(res, msg="RENAME of file into its hard link")
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of file into its hard link should do nothing, "
               "but cinfo was changed")
