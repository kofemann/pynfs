from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()
from .environment import check, fail, create_file
from block import Packer as BlockPacker, Unpacker as BlockUnpacker, \
    PNFS_BLOCK_READWRITE_DATA, pnfs_block_layoutupdate4, \
    pnfs_block_extent4
from nfs4lib import FancyNFS4Packer, get_nfstime


def testStateid1(t, env):
    """Check for proper sequence handling in layout stateids.

    FLAGS: block
    CODE: BLOCK1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    print(lo_stateid)
    if lo_stateid.seqid != 1:
        # From draft23 12.5.2 "The first successful LAYOUTGET processed by
        # the server using a non-layout stateid as an argument MUST have the
        # "seqid" field of the layout stateid in the response set to one."
        fail("Expected stateid.seqid==1, got %i" % lo_stateid.seqid)
    for i in range(6):
        # Get subsequent layouts
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                            (i+1)*8192, 8192, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        print(lo_stateid)
        if lo_stateid.seqid != i + 2:
            # From draft23 12.5.3 "After the layout stateid is established,
            # the server increments by one the value of the "seqid" in each
            # subsequent LAYOUTGET and LAYOUTRETURN response,
            fail("Expected stateid.seqid==%i, got %i" % (i+2, lo_stateid.seqid))

def testStateid2(t, env):
    """Check for proper sequence handling in layout stateids.

    FLAGS: block
    CODE: BLOCK2
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 2
    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        8192, 8192, 8192, lo_stateid1, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 3 (merge of prior two)
    lo_stateid2 = res.resarray[-1].logr_stateid
    print(lo_stateid2)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 2*8192, 2*8192, lo_stateid2, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid3 = res.resarray[-1].logr_stateid
    print(lo_stateid3)
    # lo_stateid3.seqid = 3 # BUG - work around emc problem
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    extent = opaque.blo_extents[-1]
    extent.bex_state = PNFS_BLOCK_READWRITE_DATA
    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid3,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)

def testEmptyCommit(t, env):
    """Check for proper handling of empty LAYOUTCOMMIT.

    FLAGS: block
    CODE: BLOCK3
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 2
    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        8192, 8192, 8192, lo_stateid1, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid
    print(lo_stateid2)
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    extent = opaque.blo_extents[-1]
    extent.bex_state = PNFS_BLOCK_READWRITE_DATA
    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid2,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)
    # Send another LAYOUTCOMMIT, with an empty opaque
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid2,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, ""))]
    res = sess.compound(ops)
    check(res)

def testSplitCommit(t, env):
    """Check for proper handling of disjoint LAYOUTCOMMIT.opaque

    FLAGS: block
    CODE: BLOCK4
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 2*8192, 2*8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)

    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    dev = opaque.blo_extents[-1].bex_vol_id
    extent1 = pnfs_block_extent4(dev, 0, 8192, 0, PNFS_BLOCK_READWRITE_DATA)
    extent2 = pnfs_block_extent4(dev, 8192, 8192, 0, PNFS_BLOCK_READWRITE_DATA)

    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent1,
                                                              extent2]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(0,
                           2*8192,
                           False, lo_stateid1,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)
