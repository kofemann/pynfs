from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import *
import nfs_ops
op = nfs_ops.NFS4ops()
from environment import check, fail, create_file, close_file, open_create_file_op
from xdrdef.nfs4_pack import NFS4Packer as FlexPacker, \
	NFS4Unpacker as FlexUnpacker
from nfs4lib import FancyNFS4Packer, get_nfstime

current_stateid = stateid4(1, '\0' * 12)

def check_seqid(stateid, seqid):
    if stateid.seqid != seqid:
        fail("Expected stateid.seqid==%i, got %i" % (seqid, stateid.seqid))

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

    # From draft23 12.5.2 "The first successful LAYOUTGET processed by
    # the server using a non-layout stateid as an argument MUST have the
    # "seqid" field of the layout stateid in the response set to one."
    check_seqid(lo_stateid, 1)

    for i in range(6):
        # Get subsequent layouts
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_RW,
                            (i+1)*8192, 8192, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        # From draft23 12.5.3 "After the layout stateid is established,
        # the server increments by one the value of the "seqid" in each
        # subsequent LAYOUTGET and LAYOUTRETURN response,
	check_seqid(lo_stateid, i + 2)
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

    check_seqid(lo_stateid, seqid_next)
    seqid_next += 1

    # Get the first with the lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid

    check_seqid(lo_stateid2, seqid_next)
    seqid_next += 1

    # Get the second with the original lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, 0xffffffffffffffff, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid3 = res.resarray[-1].logr_stateid

    check_seqid(lo_stateid3, seqid_next)
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
        check_seqid(lo_stateid, seqid_next)
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
    check_seqid(lo_stateid, 1)

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
    check_seqid(lo_stateid, 1)

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
    check_seqid(lo_stateid, 2)

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

def testFlexLayoutStatsSmall(t, env):
    """Open 20 "small" files and simulate LAYOUTSTATS for them
    1) OPEN, LAYOUTGET
    2) GETDEVINFO
    3) LAYOUTRETURN, CLOSE

    FLAGS: flex
    CODE: FFLS1
    """
    lats = [93089, 107683, 112340, 113195, 130412, 138390, 140427, 158824, 193078, 201879, 391634, 404757, 2201181, 2232614, 2280089, 2296343, 2341763, 2392984, 3064546, 3070314]
    durs = [3387666, 3439506, 3737081, 4448315, 4380523, 4419273, 4419746, 5903420, 5932432, 5932938, 7573082, 11085497, 11125274, 11126513, 13720303, 15990926, 16020425, 16020948, 20181628, 20213871]

    if len(lats) != len(durs):
        fail("Lats and durs not same")

    sess = env.c1.new_pnfs_client_session(env.testname(t))

    for i in range(len(lats)):
        open_op = open_create_file_op(sess, env.testname(t) + str(i), open_create=OPEN4_CREATE)
        res = sess.compound( open_op +
               [op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_RW,
                            0, 0xffffffffffffffff, 4196, current_stateid, 0xffff)])
        check(res, NFS4_OK)
        lo_stateid = res.resarray[-1].logr_stateid
        fh = res.resarray[-2].object
        open_stateid = res.resarray[-3].stateid

        check_seqid(lo_stateid, 1)

        layout = res.resarray[-1].logr_layout[-1]
        p = FlexUnpacker(layout.loc_body)
        opaque = p.unpack_ff_layout4()
        p.done()

        # Assume one mirror/storage device
        ds = opaque.ffl_mirrors[-1].ffm_data_servers[-1]

        stats_hint = opaque.ffl_stats_collect_hint

        deviceid = ds.ffds_deviceid

        ops = [op.putfh(fh),
               op.getdeviceinfo(deviceid, LAYOUT4_FLEX_FILES, 0xffffffff, 0)]
        res = sess.compound(ops)
        check(res)

        gda = res.resarray[-1].gdir_device_addr

        p = FlexUnpacker(gda.da_addr_body)
        da = p.unpack_ff_device_addr4()
        p.done()

        rd_io = io_info4(0, 0)
        wr_io = io_info4(1, 16384)

        rd_lat = ff_io_latency4(0, 0, 0, 0, 0, nfstime4(0, 0), nfstime4(0, 0))
        wr_lat = ff_io_latency4(1, 16384, 1, 16384, 0, nfstime4(0, lats[i]), nfstime4(0, lats[i]))

        offset = 0
        file_length = 16384

        dur = durs[i]
        fflu = ff_layoutupdate4(da.ffda_netaddrs[-1], ds.ffds_fh_vers[-1],
                                rd_lat, wr_lat, nfstime4(0, dur), True)

        ffio = ff_iostats4(offset, file_length, lo_stateid, rd_io, wr_io, deviceid, fflu)
        fflr = ff_layoutreturn4([], [ffio])

        p = FlexPacker()
        p.pack_ff_layoutreturn4(fflr)

        ops = [op.putfh(fh),
               op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                               layoutreturn4(LAYOUTRETURN4_FILE,
                                             layoutreturn_file4(0, 0xffffffffffffffff, lo_stateid, p.get_buffer()))),
               op.close(0, open_stateid)]
        res = sess.compound(ops)
        check(res)
