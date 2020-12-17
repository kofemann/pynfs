from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import *
import nfs_ops
op = nfs_ops.NFS4ops()
from .environment import check, fail, create_file, close_file, open_create_file_op
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
        fail("Expected uid_rd != %s, got %s" % (uid_rd, uid_rw))

    if gid_rw != gid_rd:
        fail("Expected gid_rd == %s, got %s" % (gid_rd, gid_rw))

    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutStatsSmall(t, env):
    """Open 20 "small" files and simulate LAYOUTSTATS for them
    1) OPEN, LAYOUTGET
    2) GETDEVINFO
    3) LAYOUTRETURN, CLOSE

    FLAGS: flex layoutstats
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

def _LayoutStats(t, env, stats):
    '''Loop over the provided layoutstats, sending them on in time
    '''
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
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

    stats_hint = opaque.ffl_stats_collect_hint

    # Assume one mirror/storage device
    ds = opaque.ffl_mirrors[-1].ffm_data_servers[-1]

    deviceid = ds.ffds_deviceid

    ops = [op.putfh(fh),
           op.getdeviceinfo(deviceid, LAYOUT4_FLEX_FILES, 0xffffffff, 0)]
    res = sess.compound(ops)
    check(res)

    gda = res.resarray[-1].gdir_device_addr

    p = FlexUnpacker(gda.da_addr_body)
    da = p.unpack_ff_device_addr4()
    p.done()

    rd_io = io_info4()
    wr_io = io_info4()

    rd_lat = ff_io_latency4()
    wr_lat = ff_io_latency4()

    for s in stats:
        dur = get_nfstime(s[1])

        # Did not capture these in the gathered traces
        offset = 0
        file_length = 0xffffffffffffffff
        rd_io.ii_count = 0
        rd_io.ii_bytes = 0
        wr_io.ii_count = 0
        wr_io.ii_bytes = 0

        rd_lat.ffil_ops_requested = s[5]
        rd_lat.ffil_bytes_requested = s[4]
        rd_lat.ffil_ops_completed = s[6]
        rd_lat.ffil_bytes_completed = s[2]
        rd_lat.ffil_bytes_not_delivered = s[3]
        rd_lat.ffil_total_busy_time = get_nfstime(s[7])
        rd_lat.ffil_aggregate_completion_time = get_nfstime(s[8])
        wr_lat.ffil_ops_requested = s[12]
        wr_lat.ffil_bytes_requested = s[11]
        wr_lat.ffil_ops_completed = s[13]
        wr_lat.ffil_bytes_completed = s[9]
        wr_lat.ffil_bytes_not_delivered = s[10]
        wr_lat.ffil_total_busy_time = get_nfstime(s[14])
        wr_lat.ffil_aggregate_completion_time = get_nfstime(s[15])

        sleeper = s[0]
        env.sleep(sleeper)
        fflu = ff_layoutupdate4(da.ffda_netaddrs[-1], ds.ffds_fh_vers[-1],
                                rd_lat, wr_lat, dur, True)
        p = FlexPacker()
        p.pack_ff_layoutupdate4(fflu)
        lu4 = layoutupdate4(LAYOUT4_FLEX_FILES, p.get_buffer())

        ops = [op.putfh(fh),
               op.layoutstats(offset, file_length, lo_stateid, rd_io, wr_io, deviceid, lu4)]
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

def testFlexLayoutStatsReset(t, env):
    """These layoutstats are from when the client effectively resets them
    by having one field be less than the cumulative ancestor

    FLAGS: flex layoustats
    CODE: FFLS2
    """

    ls = [[15, 14997377109, 756789248, 0, 756834304, 184774, 184763, 14996867426, 135877046309, 252579840, 0, 252665856, 61686, 61665, 14997307909, 336986104593],
          [15, 29997404625, 1527537664, 0, 1527566336, 372941, 372934, 29996142132, 275416132139, 508502016, 0, 508604416, 124171, 124146, 29997293567, 670368077434],
          [15, 44999356031, 2331115520, 0, 2331136000, 569125, 569120, 44997516473, 414235887583, 775569408, 0, 775680000, 189375, 189348, 44999096896, 1004056428600],
          [15, 60001513873, 3142483968, 0, 3142529024, 767219, 767208, 59999263507, 550956049466, 1044996096, 0, 1045082112, 255147, 255126, 60001232968, 1340163285214],
          [15, 75001564615, 3969384448, 0, 3969413120, 969095, 969088, 74999204445, 687761120289, 1320456192, 0, 1320542208, 322398, 322377, 75001158793, 1676193906267],
          [15, 90001651970, 4873195520, 0, 4873248768, 1189758, 1189745, 89999194540, 828644696229, 1620467712, 0, 1620545536, 395641, 395622, 90000994588, 2006906488984],
          [15, 105001710572, 5816430592, 0, 5816467456, 1420036, 1420027, 104995782871, 979226777566, 1935175680, 0, 1935269888, 472478, 472455, 104999171073, 2326727992588],
          [15, 14997245247, 1466019840, 0, 1466097664, 357934, 357915, 15001797989, 277140995467, 487624704, 0, 487677952, 119062, 119049, 14997939745, 179221181962],
          [15, 29999503656, 2929393664, 0, 2929500160, 715210, 715184, 30001965158, 554484427501, 974204928, 0, 974229504, 237849, 237843, 29998797328, 359060066193],
          [15, 45000138417, 4245204992, 0, 4245245952, 1036437, 1036427, 45005641995, 825579118923, 1411981312, 0, 1412071424, 344744, 344722, 44996637179, 547563519532],
          [15, 60000125536, 5545734144, 0, 5545807872, 1353957, 1353939, 60009284822, 1097378466922, 1844367360, 0, 1844400128, 450293, 450285, 59996684404, 735124264647],
          [15, 14999894874, 1278164992, 0, 1278226432, 312067, 312052, 15006094174, 270749903934, 425877504, 0, 425947136, 103991, 103974, 15000341906, 189401125380],
          [15, 30000017314, 2586595328, 0, 2586648576, 631506, 631493, 30009142707, 540229533389, 860536832, 0, 860614656, 210111, 210092, 29999220098, 379353634204],
          [15, 44999991304, 3859476480, 0, 3859574784, 942279, 942255, 45011969088, 808964878766, 1283543040, 0, 1283575808, 313373, 313365, 44999310875, 571777183394],
          [15, 60000803942, 5141098496, 0, 5141168128, 1255168, 1255151, 60015665154, 1075012244233, 1709035520, 0, 1709096960, 417260, 417245, 60000142398, 766775808737],
          [15, 75000722908, 6431453184, 0, 6431526912, 1570197, 1570179, 75018741381, 1344327593333, 2140831744, 0, 2140889088, 522678, 522664, 75000341374, 957762218131],
          [15, 14990345451, 1310584832, 0, 1310654464, 319984, 319967, 14990338511, 276432361830, 436121600, 0, 436183040, 106490, 106475, 14991353202, 182231098560],
          [15, 29990415908, 2630619136, 0, 2630701056, 642261, 642241, 29983066936, 554752250256, 875077632, 0, 875126784, 213654, 213642, 29982845793, 362758943732],
          [15, 44992404751, 3910578176, 0, 3910664192, 954752, 954731, 44982785073, 827471490050, 1300946944, 0, 1300992000, 317625, 317614, 44985003324, 549721947944]]

    _LayoutStats(t, env, ls)

def testFlexLayoutStatsStraight(t, env):
    """These stats are the same as the reset ones, but have been massaged
    to keep the server from detecting the reset. I.e., the client
    has not lost it all!

    FLAGS: flex layoustats
    CODE: FFLS3
    """

    ls = [[15, 14997377109, 756789248, 0, 756834304, 184774, 184763, 14996867426, 135877046309, 252579840, 0, 252665856, 61686, 61665, 14997307909, 336986104593],
          [15, 29997404625, 1527537664, 0, 1527566336, 372941, 372934, 29996142132, 275416132139, 508502016, 0, 508604416, 124171, 124146, 29997293567, 670368077434],
          [15, 44999356031, 2331115520, 0, 2331136000, 569125, 569120, 44997516473, 414235887583, 775569408, 0, 775680000, 189375, 189348, 44999096896, 1004056428600],
          [15, 60001513873, 3142483968, 0, 3142529024, 767219, 767208, 59999263507, 550956049466, 1044996096, 0, 1045082112, 255147, 255126, 60001232968, 1340163285214],
          [15, 75001564615, 3969384448, 0, 3969413120, 969095, 969088, 74999204445, 687761120289, 1320456192, 0, 1320542208, 322398, 322377, 75001158793, 1676193906267],
          [15, 90001651970, 4873195520, 0, 4873248768, 1189758, 1189745, 89999194540, 828644696229, 1620467712, 0, 1620545536, 395641, 395622, 90000994588, 2006906488984],
          [15, 105001710572, 5816430592, 0, 5816467456, 1420036, 1420027, 104995782871, 979226777566, 1935175680, 0, 1935269888, 472478, 472455, 104999171073, 2326727992588],
          [15, 119998955819, 7282450432, 0, 7282565120, 1777970, 1777942, 119997580860, 1256367773033, 2422800384, 0, 2422947840, 591540, 591504, 119997110818, 2505949174550],
          [15, 135001214228, 8745824256, 0, 8745967616, 2135246, 2135211, 134997748029, 1533711205067, 2909380608, 0, 2909499392, 710327, 710298, 134997968401, 2685788058781],
          [15, 150001848989, 10061635584, 0, 10061713408, 2456473, 2456454, 150001424866, 1804805896489, 3347156992, 0, 3347341312, 817222, 817177, 149995808252, 2874291512120],
          [15, 165001836108, 11362164736, 0, 11362275328, 2773993, 2773966, 165005067693, 2076605244488, 3779543040, 0, 3779670016, 922771, 922740, 164995855477, 3061852257235],
          [15, 180001730982, 12640329728, 0, 12640501760, 3086060, 3086018, 180011161867, 2347355148422, 4205420544, 0, 4205617152, 1026762, 1026714, 179996197383, 3251253382615],
          [15, 195001853422, 13948760064, 0, 13948923904, 3405499, 3405459, 195014210400, 2616834777877, 4640079872, 0, 4640284672, 1132882, 1132832, 194995075575, 3441205891439],
          [15, 210001827412, 15221641216, 0, 15221850112, 3716272, 3716221, 210017036781, 2885570123254, 5063086080, 0, 5063245824, 1236144, 1236105, 209995166352, 3633629440629],
          [15, 225002640050, 16503263232, 0, 16503443456, 4029161, 4029117, 225020732847, 3151617488721, 5488578560, 0, 5488766976, 1340031, 1339985, 224995997875, 3828628065972],
          [15, 240002559016, 17793617920, 0, 17793802240, 4344190, 4344145, 240023809074, 3420932837821, 5920374784, 0, 5920559104, 1445449, 1445404, 239996196851, 4019614475366],
          [15, 254992904467, 19104202752, 0, 19104456704, 4664174, 4664112, 255014147585, 3697365199651, 6356496384, 0, 6356742144, 1551939, 1551879, 254987550053, 4201845573926],
          [15, 269992974924, 20424237056, 0, 20424503296, 4986451, 4986386, 270006876010, 3975685088077, 6795452416, 0, 6795685888, 1659103, 1659046, 269979042644, 4382373419098],
          [15, 284994963767, 21704196096, 0, 21704466432, 5298942, 5298876, 285006594147, 4248404327871, 7221321728, 0, 7221551104, 1763074, 1763018, 284981200175, 4569336423310]]
    _LayoutStats(t, env, ls)

def testFlexLayoutStatsOverflow(t, env):
    """These layoutstats are a write intensive work load in which eventually one stat takes
    twice longer than the collection period.

    FLAGS: flex layoustats
    CODE: FFLS4
    """

    ls = [[27, 27614183359, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 96468992, 10292, 10240, 26609085208, 134047775590766],
          [15, 42725368747, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 2402213888, 15847, 11881, 31458638093, 136367242297571],
          [15, 57912190475, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 2406907904, 15924, 11881, 31458638093, 136367242297571],
          [15, 72921814168, 0, 0, 0, 0, 0, 0, 0, 896532480, 0, 2946293760, 16847, 15969, 70391696445, 275087250172195],
          [15, 87922239746, 0, 0, 0, 0, 0, 0, 0, 896532480, 0, 3196473344, 18335, 15969, 70391696445, 275087250172195],
          [15, 102949476399, 0, 0, 0, 0, 0, 0, 0, 1808183296, 0, 4038545408, 20452, 19074, 92455324261, 310159328537298],
          [15, 117951351182, 0, 0, 0, 0, 0, 0, 0, 2587693056, 0, 4486782976, 22613, 19935, 116950745229, 331739899803911],
          [16, 133017224561, 0, 0, 0, 0, 0, 0, 0, 2587693056, 0, 4830961664, 23306, 22169, 118004988775, 353778424445917],
          [15, 148031127154, 0, 0, 0, 0, 0, 0, 0, 4132970496, 0, 5960671232, 29861, 26094, 146128115965, 387064682636158],
          [15, 163058556237, 0, 0, 0, 0, 0, 0, 0, 5614419968, 0, 7550558208, 40590, 39198, 159139080717, 453635077855389],
          [15, 178067770476, 0, 0, 0, 0, 0, 0, 0, 5614419968, 0, 7838756864, 41554, 39198, 159139080717, 453635077855389],
          [15, 193081456711, 0, 0, 0, 0, 0, 0, 0, 6428528640, 0, 8151494656, 43497, 42179, 189486399712, 517147615890054],
          [15, 208082626131, 0, 0, 0, 0, 0, 0, 0, 7284596736, 0, 8656367616, 47929, 43079, 207082978313, 532741795045495],
          [15, 223082643294, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9539055616, 58212, 53705, 222083467525, 636168303637199],
          [15, 238083127306, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9763426304, 62673, 57863, 223491351125, 650450833313121],
          [15, 253175262253, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9860571136, 65509, 57863, 223491351125, 650450833313121],
          [15, 268185316876, 0, 0, 0, 0, 0, 0, 0, 8729772032, 0, 10523738112, 71014, 65222, 267165070170, 853839631006322],
          [17, 285787666679, 0, 0, 0, 0, 0, 0, 0, 9522692096, 0, 10779361280, 72612, 66965, 284787142241, 896650223319399],
          [33, 318568880195, 0, 0, 0, 0, 0, 0, 0, 9522692096, 0, 10779361280, 72613, 72611, 317562885639, 1120229814239633],
          [15, 333747489171, 0, 0, 0, 0, 0, 0, 0, 10788278272, 0, 10788802560, 74918, 74790, 332233465692, 1121703181284495],
          [15, 348749618256, 0, 0, 0, 0, 0, 0, 0, 10801360896, 0, 10801885184, 78112, 77984, 347235605251, 1123668237106158],
          [14, 362014682745, 0, 0, 0, 0, 0, 0, 0, 10812923904, 0, 10814496768, 81191, 80935, 361134569864, 1125289046746198],
          [15, 377016435231, 0, 0, 0, 0, 0, 0, 0, 10836291584, 0, 10837864448, 86896, 86640, 376136316640, 1127198465086932],
          [15, 392027464946, 0, 0, 0, 0, 0, 0, 0, 10852364288, 0, 10853937152, 90820, 90564, 391147321463, 1129113173731145],
          [15, 407034683097, 0, 0, 0, 0, 0, 0, 0, 10864914432, 0, 10866487296, 93884, 93628, 406154554429, 1131023767183211]]
    _LayoutStats(t, env, ls)

def layoutget_return(sess, fh, open_stateid, layout_iomode=LAYOUTIOMODE4_RW,
                     layout_error=None, layout_error_op=OP_WRITE):
    """
    Perform LAYOUTGET and LAYOUTRETURN
    """

    # Get layout
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES, layout_iomode,
                        0, NFS4_UINT64_MAX, 4196, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    layout_stateid = res.resarray[-1].logr_stateid

    # Return layout
    if not layout_error:  # Return regular layout
        ops = [op.putfh(fh),
               op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                               layoutreturn4(LAYOUTRETURN4_FILE,
                                             layoutreturn_file4(0, NFS4_UINT64_MAX,
                                                                layout_stateid, "")))]
    else:  # Return layout with error
        # Get device id
        locb = res.resarray[-1].logr_layout[0].lo_content.loc_body
        p = FlexUnpacker(locb)
        layout = p.unpack_ff_layout4()
        p.done()

        deviceid = layout.ffl_mirrors[0].ffm_data_servers[0].ffds_deviceid
        deverr = device_error4(deviceid, layout_error, layout_error_op)
        ffioerr = ff_ioerr4(0, NFS4_UINT64_MAX, layout_stateid, [deverr])
        fflr = ff_layoutreturn4([ffioerr], [])

        p = FlexPacker()
        p.pack_ff_layoutreturn4(fflr)

        ops = [op.putfh(fh),
               op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                               layoutreturn4(LAYOUTRETURN4_FILE,
                                             layoutreturn_file4(0, NFS4_UINT64_MAX,
                                                                layout_stateid,
                                                                p.get_buffer())))]

    res2 = sess.compound(ops)
    check(res2)
    return [res, res2]

def get_layout_cred(logr):
    """
    :summary: Returns credentials contained in LAYOUTGET reply
    :param logr: LAYOUTGET reply result
    :return: List with uid and gid
    """
    locb = logr.logr_layout[0].lo_content.loc_body
    p = FlexUnpacker(locb)
    layout = p.unpack_ff_layout4()
    p.done()
    uid = layout.ffl_mirrors[0].ffm_data_servers[0].ffds_user
    gid = layout.ffl_mirrors[0].ffm_data_servers[0].ffds_group
    return [uid, gid]

def testFlexLayoutReturnNxioRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_NXIO for READ

    FLAGS: flex layoutreturn
    CODE: FFLORNXIOREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ, NFS4ERR_NXIO, OP_READ)

    # Obtain another layout
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnNxioWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_NXIO for WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORNXIOWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_NXIO, OP_WRITE)

    # Obtain another layout
    layoutget_return(sess, fh, open_stateid)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnStaleRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_STALE for READ

    FLAGS: flex layoutreturn
    CODE: FFLORSTALEREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ, NFS4ERR_STALE, OP_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnStaleWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_STALE for WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORSTALEWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_STALE, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnIoRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_IO for READ

    FLAGS: flex layoutreturn
    CODE: FFLORIOREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ, NFS4ERR_IO, OP_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnIoWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_IO for WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORIOWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_IO, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnServerFaultRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_SERVERFAULT on READ

    FLAGS: flex layoutreturn
    CODE: FFLORSERVERFAULTREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ, NFS4ERR_SERVERFAULT, OP_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnServerFaultWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_SERVERFAULT on WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORSERVERFAULTWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_SERVERFAULT, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnNospc(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_NOSPC

    FLAGS: flex layoutreturn
    CODE: FFLORNOSPC
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_NOSPC, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnFbig(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_FBIG

    FLAGS: flex layoutreturn
    CODE: FFLORFBIG
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_FBIG, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnAccessRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_ACCESS on READ

    FLAGS: flex layoutreturn
    CODE: FFLORACCESSREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ,
                     NFS4ERR_ACCESS, OP_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnAccessWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_ACCESS on WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORACCESSWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW,
                     NFS4ERR_ACCESS, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnDelayRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_DELAY on READ

    FLAGS: flex layoutreturn
    CODE: FFLORDELAYREAD
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_READ, NFS4ERR_DELAY, OP_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnDelayWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_DELAY on WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORDELAYWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, LAYOUTIOMODE4_RW, NFS4ERR_DELAY, OP_WRITE)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturn1K(t, env):
    """
    Perform LAYOUTGET and LAYOUTRETURN 1K times with error being returned periodically

    FLAGS: flex layoutreturn
    CODE: FFLOR1K
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    count = 1000  # Repeat LAYOUTGET/LAYOUTRETURN count times
    layout_error_ratio = 10  # Send an error every layout_error_ratio layout returns

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    for i in xrange(count):
        layout_error = None if i % layout_error_ratio else NFS4ERR_ACCESS
        layoutget_return(sess, fh, open_stateid, layout_error=layout_error)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)
