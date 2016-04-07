from xdrdef.nfs4_const import *
from environment import check, fail, maketree, rename_obj, get_invalid_utf8strings, create_obj, create_confirm, link, use_obj, create_file
import nfs_ops
op = nfs_ops.NFS4ops()
from xdrdef.nfs4_type import *

def testValidDir(t, env):
    """RENAME : normal operation

    FLAGS: rename dir all
    CODE: RNM1d
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1', ['foo']], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of directory %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidFile(t, env):
    """RENAME : normal operation

    FLAGS: rename file all
    CODE: RNM1r
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1', 'foo'], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of file %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidLink(t, env):
    """RENAME : normal operation

    FLAGS: rename symlink all
    CODE: RNM1a
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4LNK, linkdata=env.linkdata))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of symlink %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidBlock(t, env):
    """RENAME : normal operation

    FLAGS: rename block all
    CODE: RNM1b
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4BLK, devdata=specdata4(1, 2)))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of block device %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidChar(t, env):
    """RENAME : normal operation

    FLAGS: rename char all
    CODE: RNM1c
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], createtype4(NF4BLK, devdata=specdata4(1, 2)))
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of character device %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidFifo(t, env):
    """RENAME : normal operation

    FLAGS: rename fifo all
    CODE: RNM1f
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], NF4FIFO)
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of fifo %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testValidSocket(t, env):
    """RENAME : normal operation

    FLAGS: rename socket all
    CODE: RNM1s
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2']])
    res = create_obj(sess, basedir + ['dir1', 'foo'], NF4SOCK)
    check(res)
    res = rename_obj(sess, basedir + ['dir1', 'foo'], basedir + ['dir2', 'bar'])
    check(res, msg="RENAME of socket %s/dir1/foo to %s/dir2/bar" %
          (name, name))

def testSfhFile(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename file all
    CODE: RNM2r
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.usefile + [name], env.c1.homedir + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhLink(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename symlink all
    CODE: RNM2a
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.uselink + [name], env.c1.homedir + [name])
    check(res, [NFS4ERR_SYMLINK, NFS4ERR_NOTDIR], "RENAME with non-dir <sfh>")

def testSfhBlock(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename block all
    CODE: RNM2b
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.useblock + [name], env.c1.homedir + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhChar(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename char all
    CODE: RNM2c
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.usechar + [name], env.c1.homedir + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhFifo(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename fifo all
    CODE: RNM2f
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.usefifo + [name], env.c1.homedir + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testSfhSocket(t, env):
    """RENAME with non-dir (sfh) should return NFS4ERR_NOTDIR

    FLAGS: rename socket all
    CODE: RNM2s
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = rename_obj(sess, env.opts.usesocket + [name], env.c1.homedir + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <sfh>")

def testCfhFile(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename file all
    CODE: RNM3r
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.usefile + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhLink(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename symlink all
    CODE: RNM3a
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.uselink + [name])
    check(res, [NFS4ERR_NOTDIR, NFS4ERR_SYMLINK],
                                "RENAME with non-dir <cfh>")

def testCfhBlock(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename block all
    CODE: RNM3b
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.useblock + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhChar(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename char all
    CODE: RNM3c
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.usechar + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhFifo(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename fifo all
    CODE: RNM3f
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.usefifo + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testCfhSocket(t, env):
    """RENAME with non-dir (cfh) should return NFS4ERR_NOTDIR

    FLAGS: rename socket all
    CODE: RNM3s
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    res = create_obj(sess, env.c1.homedir + [name])
    check(res)
    res = rename_obj(sess, env.c1.homedir + [name], env.opts.usesocket + [name])
    check(res, NFS4ERR_NOTDIR, "RENAME with non-dir <cfh>")

def testNoSfh(t, env):
    """RENAME without (sfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: rename emptyfh all
    CODE: RNM4
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    ops = env.home + [op.rename(name, name)]
    res = sess.compound(ops)
    check(res, NFS4ERR_NOFILEHANDLE, "RENAME with no <sfh>")

# FRED - can't test No Cfh, with a Sfh

def testNonExistent(t, env):
    """RENAME on non-existing object should return NFS4ERR_NOENT

    FLAGS: rename all
    CODE: RNM5
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + ['foo'], basedir + ['bar'])
    check(res, NFS4ERR_NOENT, "RENAME on non-existing object %s/foo" % name)

def testZeroLengthOldname(t, env):
    """RENAME with zero length oldname should return NFS4ERR_INVAL

    FLAGS: rename all
    CODE: RNM6
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + [''], basedir + ['bar'])
    check(res, NFS4ERR_INVAL, "RENAME with zero length oldname")

def testZeroLengthNewname(t, env):
    """RENAME with zero length newname should return NFS4ERR_INVAL

    FLAGS: rename all
    CODE: RNM7
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    res = create_obj(sess, basedir)
    check(res)
    res = rename_obj(sess, basedir + ['foo'], basedir + [''])
    check(res, NFS4ERR_INVAL, "RENAME with zero length newname")

def testBadutf8Oldname(t, env):
    """RENAME with non-UTF8 oldname should return NFS4ERR_INVAL

    FLAGS: rename utf8 ganesha
    CODE: RNM8
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    res = create_obj(sess, basedir)
    check(res)
    for bad_utf8 in get_invalid_utf8strings():
        res = rename_obj(sess, basedir + [bad_utf8], basedir + [name])
        check(res, NFS4ERR_INVAL, "RENAME with non-UTF8 oldname %s/%s" %
                                   (name, repr(bad_utf8)[1:-1]))

def testBadutf8Newname(t, env):
    """RENAME with non-UTF8 newname should return NFS4ERR_INVAL

    FLAGS: rename utf8 ganesha
    CODE: RNM9
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, [name]])
    for bad_utf8 in get_invalid_utf8strings():
        res = rename_obj(sess, basedir + [name], basedir + [bad_utf8])
        check(res, NFS4ERR_INVAL, "RENAME with non-UTF8 newname %s/%s" %
                                   (name, repr(bad_utf8)[1:-1]))

def testDotsOldname(t, env):
    """RENAME from nonexistant . or .. should return _NOENT/_BADNAME

    FLAGS: rename dots all
    CODE: RNM10
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, [name]])
    res = rename_obj(sess, basedir + ['.'], basedir + [name])
    check(res, NFS4ERR_BADNAME, "RENAME from nonexistant '.'",
          [NFS4ERR_NOENT])
    res = rename_obj(sess, basedir + ['..'], basedir + [name])
    check(res, NFS4ERR_BADNAME, "RENAME from nonexistant '..'",
          [NFS4ERR_NOENT])

def testDotsNewname(t, env):
    """RENAME into . or .. should return _BADNAME or NFS4_OK

    FLAGS: rename dots all
    CODE: RNM11
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, [name]])
    res = rename_obj(sess, basedir + [name], basedir + ['.'])
    check(res, NFS4ERR_BADNAME, "RENAME into '.'",
          [NFS4_OK])
    res = rename_obj(sess, basedir + [name], basedir + ['..'])
    check(res, NFS4ERR_BADNAME, "RENAME into '..'",
          [NFS4_OK])

def testDirToObj(t, env):
    """RENAME dir into existing nondir should fail

    FLAGS: rename all
    CODE: RNM12
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir'], 'file'])
    res = rename_obj(sess, basedir + ['dir'], basedir + ['file'])
    # note rfc 3530 and 1813 specify EXIST, but posix specifies NOTDIR
    check(res, [NFS4ERR_EXIST, NFS4ERR_NOTDIR], "RENAME dir into existing file")

def testDirToDir(t, env):
    """RENAME dir into existing, empty dir should retrun NFS4_OK

    FLAGS: rename all
    CODE: RNM13
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1', ['foo']], ['dir2']])
    res = rename_obj(sess, basedir + ['dir1'], basedir + ['dir2'])
    check(res, msg="RENAME dir1 into existing, empty dir2")

def testFileToDir(t, env):
    """RENAME file into existing dir should fail

    FLAGS: rename all
    CODE: RNM14
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir'], 'file'])
    res = rename_obj(sess, basedir + ['file'], basedir + ['dir'])
    # note rfc 3530 and 1813 specify EXIST, but posix specifies ISDIR
    check(res, [NFS4ERR_EXIST, NFS4ERR_ISDIR], "RENAME file into existing dir")

def testFileToFile(t, env):
    """RENAME file into existing file should return NFS4_OK

    FLAGS: rename all
    CODE: RNM15
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, 'file1', 'file2'])
    res = rename_obj(sess, basedir + ['file1'], basedir + ['file2'])
    check(res, msg="RENAME file1 into existing file2")

def testDirToFullDir(t, env):
    """RENAME dir into existing, nonempty dir should return NFS4ERR_EXIST

    FLAGS: rename all
    CODE: RNM16
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, ['dir1'], ['dir2', ['foo']]])
    res = rename_obj(sess, basedir + ['dir1'], basedir + ['dir2'])
    check(res, [NFS4ERR_EXIST, NFS4ERR_NOTEMPTY], "RENAME dir1 into existing, nonempty dir2")

def testFileToFullDir(t, env):
    """RENAME file into existing, nonempty dir should fail

    FLAGS: rename all
    CODE: RNM17
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    basedir = env.c1.homedir + [name]
    maketree(sess, [name, 'file', ['dir', ['foo']]])
    res = rename_obj(sess, basedir + ['file'], basedir + ['dir'])
    # note rfc 3530 and 1813 specify EXIST, but posix specifies ISDIR
    check(res, [NFS4ERR_EXIST, NFS4ERR_ISDIR], "RENAME file into existing, nonempty dir")


def testSelfRenameDir(t, env):
    """RENAME that does nothing

    FLAGS: rename all
    CODE: RNM18
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    maketree(sess, [name])
    basedir = env.c1.homedir + [name]
    res = rename_obj(sess, basedir, basedir)
    check(res)
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of dir %s into itself should do nothing, "
               "but cinfo was changed" % name)

def testSelfRenameFile(t, env):
    """RENAME that does nothing

    FLAGS: rename all
    CODE: RNM19
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    fh, stateid = create_confirm(sess, name)
    basedir = env.c1.homedir + [name]
    res = rename_obj(sess, basedir, basedir)
    check(res)
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of file %s into itself should do nothing, "
               "but cinfo was changed" % name)

def testLinkRename(t, env):
    """RENAME of file into its hard link should do nothing

    FLAGS: rename all
    CODE: RNM20
    """
    name = env.testname(t)
    sess = env.c1.new_client_session(name)
    maketree(sess, [name, 'file'])
    basedir = env.c1.homedir + [name]
    res = link(sess, basedir + ['file'], basedir + ['link'])
    check(res)
    res = rename_obj(sess, basedir + ['file'], basedir + ['link'])
    check(res, msg="RENAME of file into its hard link")
    scinfo = res.resarray[-1].source_cinfo
    tcinfo = res.resarray[-1].target_cinfo
    if scinfo.before != scinfo.after or tcinfo.before != tcinfo.after:
        t.fail("RENAME of file into its hard link should do nothing, "
               "but cinfo was changed")
