from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import *
import nfs_ops
op = nfs_ops.NFS4ops()
from environment import check, fail, create_file, close_file
from xdrdef.nfs4_pack import NFS4Packer as FlexPacker, \
	NFS4Unpacker as FlexUnpacker
from nfs4lib import FancyNFS4Packer, get_nfstime

def testStateid1(t, env):
    """Check for proper sequence handling in layout stateids.

    FLAGS: flex
    CODE: FFST1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    if lo_stateid.seqid != 1:
        # From draft23 12.5.2 "The first successful LAYOUTGET processed by
        # the server using a non-layout stateid as an argument MUST have the
        # "seqid" field of the layout stateid in the response set to one."
        fail("Expected stateid.seqid==1, got %i" % lo_stateid.seqid)
    for i in range(6):
        # Get subsequent layouts
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_RW,
                            (i+1)*8192, 8192, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        if lo_stateid.seqid != i + 2:
            # From draft23 12.5.3 "After the layout stateid is established,
            # the server increments by one the value of the "seqid" in each
            # subsequent LAYOUTGET and LAYOUTRETURN response,
            fail("Expected stateid.seqid==%i, got %i" % (i+2, lo_stateid.seqid))
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexGetLayout(t, env):
    """Verify layout handling

    FLAGS: flex
    CODE: FFGLO1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_READ,
                        0, 0xffffffffffffffff, 4196, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Parse opaque
    for layout in  res.resarray[-1].logr_layout:
        if layout.loc_type == LAYOUT4_FLEX_FILES:
            p = FlexUnpacker(layout.loc_body)
            opaque = p.unpack_ff_layout4()
            p.done()
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnFile(t, env):
    """
    Return a file's layout

    FLAGS: flex
    DEPEND: FFGLO1
    CODE: FFLOR1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_READ,
                        0, 0xffffffffffffffff, 4196, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Return layout
    layout_stateid = res.resarray[-1].logr_stateid
    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, 0xffffffffffffffff, layout_stateid, "")))]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutOldSeqid(t, env):
    """Check that we do not get NFS4ERR_OLD_STATEID if we send
    two LAYOUTGETS in a row without bumping the seqid

    FLAGS: flex
    CODE: FFLOOS
    """
    seqid_next = 1
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)

    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid

    if lo_stateid.seqid != seqid_next:
        fail("Expected stateid.seqid==%i, got %i" % (seqid_next, lo_stateid.seqid))
    seqid_next += 1

    # Get the first with the lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid

    if lo_stateid2.seqid != seqid_next:
        fail("Expected stateid.seqid==%i, got %i" % (seqid_next, lo_stateid2.seqid))
    seqid_next += 1

    # Get the second with the original lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid3 = res.resarray[-1].logr_stateid

    if lo_stateid3.seqid != seqid_next:
        fail("Expected stateid.seqid==%i, got %i" % (seqid_next, lo_stateid3.seqid))
    seqid_next += 1

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, 0xffffffffffffffff, lo_stateid, "")))]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutStress(t, env):
    """Alternate LAYOUTIOMODE4_RW/LAYOUTIOMODE4_READ layout segments in the file

    FLAGS: flex
    CODE: FFLG2
    """
    seqid_next = 1
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)

    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    lo_stateid = open_stateid

    for i in range(1000):
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_FLEX_FILES,
                            LAYOUTIOMODE4_READ if i%2  else LAYOUTIOMODE4_RW,
                            0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        if lo_stateid.seqid != seqid_next:
            fail("Expected stateid.seqid==%i, got %i" % (seqid_next, lo_stateid.seqid))
        seqid_next += 1

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, 0xffffffffffffffff, lo_stateid, "")))]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexGetDevInfo(t, env):
    """Get the device info

    FLAGS: flex
    CODE: FFGDI1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    lo_stateid = open_stateid

    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    if lo_stateid.seqid != 1:
        fail("Expected stateid.seqid==%i, got %i" % (1, lo_stateid.seqid))

    layout = res.resarray[-1].logr_layout[-1]
    p = FlexUnpacker(layout.loc_body)
    opaque = p.unpack_ff_layout4()
    p.done()

    # Assume one mirror/storage device
    ds = opaque.ffl_mirrors[-1].ffm_data_servers[-1]

    deviceid = ds.ffds_deviceid

    ops = [op.putfh(fh),
           op.getdeviceinfo(deviceid, LAYOUT4_FLEX_FILES, 0xffffffff, 0)]
    res = sess.compound(ops)
    check(res)

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, 0xffffffffffffffff, lo_stateid, "")))]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutTestAccess(t, env):
    """Get both a LAYOUTIOMODE4_RW and LAYOUTIOMODE4_READ segment
    making sure that they have the same gid, but a different uid.

    FLAGS: flex
    CODE: FFLA1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    if lo_stateid.seqid != 1:
        fail("Expected stateid.seqid==%i, got %i" % (1, lo_stateid.seqid))

    layout = res.resarray[-1].logr_layout[-1]
    p = FlexUnpacker(layout.loc_body)
    opaque = p.unpack_ff_layout4()
    p.done()

    # Assume one mirror/storage device
    ds = opaque.ffl_mirrors[-1].ffm_data_servers[-1]

    uid_rw = ds.ffds_user
    gid_rw = ds.ffds_group

    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_READ,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    if lo_stateid.seqid != 2:
        fail("Expected stateid.seqid==%i, got %i" % (2, lo_stateid.seqid))

    layout = res.resarray[-1].logr_layout[-1]
    p = FlexUnpacker(layout.loc_body)
    opaque = p.unpack_ff_layout4()
    p.done()

    # Assume one mirror/storage device
    ds = opaque.ffl_mirrors[-1].ffm_data_servers[-1]

    uid_rd = ds.ffds_user
    gid_rd = ds.ffds_group

    if uid_rw == uid_rd:
        fail("Expected uid_rd != %i, got %i" % (uid_rd, uid_rw))

    if gid_rw != gid_rd:
        fail("Expected gid_rd == %i, got %i" % (gid_rd, gid_rw))

    res = close_file(sess, fh, stateid=open_stateid)
    check(res)
