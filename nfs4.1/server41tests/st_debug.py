from .st_create_session import create_session
from xdrdef.nfs4_const import *
from .environment import check, fail, create_file, close_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading

def testSupported2(t, env):
    """Check OPEN delegation handling

    FLAGS: open all
    CODE: OPEN200
    """
    # c1 - OPEN - READ with delegation
    c1 = env.c1.new_client("%s_1" % env.testname(t))
    sess1 = c1.create_session()
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    check(res) # STUB Should check delegation was granted
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid
    # c2 - OPEN - WRITE
    c2 = env.c1.new_client("%s_2" % env.testname(t))
    sess2 = c2.create_session()
    owner = open_owner4(0, "My Open Owner 2")
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
    res = sess2.compound(env.home + [open_op])
    # STUB - since we are not handling callback, deleg_return never gets done
    print(res)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    res = close_file(sess1, fh1, stateid=stateid1)
    check(res)
    res = close_file(sess2, fh2, stateid=stateid2)
    check(res)
    
def testReadWrite(t, env):
    """Do a simple READ and WRITE

    FLAGS: open all
    CODE: OPEN400
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    owner = open_owner4(0, "My Open Owner")
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, {FATTR4_SIZE:0}))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH , OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
    fh_op = op.putrootfh()
    res = sess1.compound([fh_op, open_op, op.getfh()]) # OPEN
    print(res)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, "write test data")])
    print(res)
    check(res)
    res = sess1.compound([op.putfh(fh), op.read(stateid, 0, 1000)])
    print(res)
    check(res)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testDeadlock(t, env):
    """Trigger deadlock bug

    FLAGS: debug all
    CODE: DEBUG1
    """
    c1 = env.c1.new_client(env.testname(t))
    sess1 = c1.create_session()
    owner = open_owner4(0, "My Open Owner")
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, {FATTR4_SIZE:0}))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH , OPEN4_SHARE_DENY_NONE,
                      owner, how, claim)
    res = sess1.compound(env.home + [open_op, op.getfh()]) # OPEN
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    ####
    def ops(i):
        return [op.putfh(fh),
                op.write(stateid, i*1000, UNSTABLE4, chr(97+i)*100),
                op.getattr(42950721818)
                ]
    xids = [sess1.compound_async(ops(i), slot=i) for i in range(4)]
    for xid in xids:
        res = sess1.listen(xid)
        check(res)
        print(res)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testLayout(t, env):
    """Verify layout handling

    FLAGS: layout all
    CODE: LAYOUT1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    blocksize = get_blocksize(sess, use_obj(env.opts.path))
    # Open the file
    owner = "owner for %s" % env.testname(t)
    # openres = open_file(sess, owner, env.opts.path + ["simple_extent"])
    openres = open_file(sess, owner, env.opts.path + ["hole_between_extents"])
    check(openres)
    # Get a layout
    fh = openres.resarray[-1].object
    stateid = res.resarray[-2].stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_READ,
                        0, 0xffffffff, 4*blocksize, 0xffff)]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
    
def testGetDevList(t, env):
    """Check devlist

    FLAGS: layout all
    CODE: LAYOUT2
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Test that fs handles block layouts
    ops = use_obj(env.opts.path) + [op.getattr(1<<FATTR4_FS_LAYOUT_TYPES)]
    res = sess.compound(ops)
    check(res)
    if FATTR4_FS_LAYOUT_TYPES not in res.resarray[-1].obj_attributes:
        fail("fs_layout_type not available")
    if LAYOUT4_BLOCK_VOLUME not in res.resarray[-1].obj_attributes[FATTR4_FS_LAYOUT_TYPES]:
        fail("layout_type does not contain BLOCK")
    # Send GETDEVICELIST
    ops = use_obj(env.opts.path) + [op.getdevicelist(LAYOUT4_BLOCK_VOLUME, 0, 0, "")]
    res = sess.compound(ops)
    check(res)
