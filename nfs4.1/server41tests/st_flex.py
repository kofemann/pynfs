from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import *
import nfs_ops
op = nfs_ops.NFS4ops()
from .environment import check, fail, create_file, close_file, open_create_file_op
from xdrdef.nfs4_pack import NFS4Packer as FlexPacker, \
    NFS4Unpacker as FlexUnpacker
from nfs4lib import FancyNFS4Packer, get_nfstime

current_stateid = stateid4(1, b'\0' * 12)

empty_fflr = ff_layoutreturn4([], [])

empty_p = FlexPacker()
empty_p.pack_ff_layoutreturn4(empty_fflr)

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

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
    res = sess.compound(ops)
    check(res)

    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnFile(t, env):
    """
    Return a file's layout

    FLAGS: flex
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
                        0, NFS4_MAXFILELEN, 4196, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Return layout
    lo_stateid = res.resarray[-1].logr_stateid

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
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
                        0, NFS4_MAXFILELEN, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid

    check_seqid(lo_stateid, seqid_next)
    seqid_next += 1

    # Get the first with the lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, NFS4_MAXFILELEN, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid

    check_seqid(lo_stateid2, seqid_next)
    seqid_next += 1

    # Get the second with the original lo_stateid
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES,
                        LAYOUTIOMODE4_RW,
                        0, NFS4_MAXFILELEN, 8192, lo_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid3 = res.resarray[-1].logr_stateid

    check_seqid(lo_stateid3, seqid_next)
    seqid_next += 1

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
    res = sess.compound(ops)
    check(res, NFS4ERR_OLD_STATEID, "LAYOUTRETURN with an old stateid")

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid3, empty_p.get_buffer())))]
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
                            LAYOUTIOMODE4_READ if i%2 else LAYOUTIOMODE4_RW,
                            0, NFS4_MAXFILELEN, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        check_seqid(lo_stateid, seqid_next)
        seqid_next += 1

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
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
                        0, NFS4_MAXFILELEN, 8192, lo_stateid, 0xffff)]
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
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
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
                        0, NFS4_MAXFILELEN, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid1 = res.resarray[-1].logr_stateid
    check_seqid(lo_stateid1, 1)

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
                        0, NFS4_MAXFILELEN, 8192, lo_stateid1, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid
    check_seqid(lo_stateid2, 2)

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

    ops = [op.putfh(fh),
           op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                           layoutreturn4(LAYOUTRETURN4_FILE,
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid2, empty_p.get_buffer())))]
    res = sess.compound(ops)
    check(res)

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
        open_op = open_create_file_op(sess, b'%s_%i' % (env.testname(t), i), open_create=OPEN4_CREATE)
        res = sess.compound(open_op +
               [op.layoutget(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_RW,
                            0, NFS4_MAXFILELEN, 4196, current_stateid, 0xffff)])
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
                                             layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                                lo_stateid, p.get_buffer()))),
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
                        0, NFS4_MAXFILELEN, 8192, lo_stateid, 0xffff)]
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
        file_length = NFS4_MAXFILELEN
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
                                         layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                            lo_stateid, empty_p.get_buffer())))]
    res = sess.compound(ops)
    check(res)
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutStatsReset(t, env):
    """These layoutstats are from when the client effectively resets them
    by having one field be less than the cumulative ancestor

    FLAGS: flex layoutstats
    CODE: FFLS2
    """

    ls = [[1, 999825140, 756789248, 0, 756834304, 184774, 184763, 999791161, 9058469753, 252579840, 0, 252665856, 61686, 61665, 999820527, 22465740306],
          [1, 1999826975, 1527537664, 0, 1527566336, 372941, 372934, 1999742808, 18361075475, 508502016, 0, 508604416, 124171, 124146, 1999819571, 44691205162],
          [1, 2999957068, 2331115520, 0, 2331136000, 569125, 569120, 2999834431, 27615725838, 775569408, 0, 775680000, 189375, 189348, 2999939793, 66937095240],
          [1, 4000100924, 3142483968, 0, 3142529024, 767219, 767208, 3999950900, 36730403297, 1044996096, 0, 1045082112, 255147, 255126, 4000082197, 89344219014],
          [1, 5000104307, 3969384448, 0, 3969413120, 969095, 969088, 4999946963, 45850741352, 1320456192, 0, 1320542208, 322398, 322377, 5000077252, 111746260417],
          [1, 6000110131, 4873195520, 0, 4873248768, 1189758, 1189745, 5999946302, 55242979748, 1620467712, 0, 1620545536, 395641, 395622, 6000066305, 133793765932],
          [1, 7000114038, 5816430592, 0, 5816467456, 1420036, 1420027, 6999718858, 65281785171, 1935175680, 0, 1935269888, 472478, 472455, 6999944738, 155115199505],
          [1, 999816349, 1466019840, 0, 1466097664, 357934, 357915, 1000119865, 18476066364, 487624704, 0, 487677952, 119062, 119049, 999862649, 11948078797],
          [1, 1999966910, 2929393664, 0, 2929500160, 715210, 715184, 2000131010, 36965628500, 974204928, 0, 974229504, 237849, 237843, 1999919821, 23937337746],
          [1, 3000009227, 4245204992, 0, 4245245952, 1036437, 1036427, 3000376133, 55038607928, 1411981312, 0, 1412071424, 344744, 344722, 2999775811, 36504234635],
          [1, 4000008369, 5545734144, 0, 5545807872, 1353957, 1353939, 4000618988, 73158564461, 1844367360, 0, 1844400128, 450293, 450285, 3999778960, 49008284309],
          [1, 999992991, 1278164992, 0, 1278226432, 312067, 312052, 1000406278, 18049993595, 425877504, 0, 425947136, 103991, 103974, 1000022793, 12626741692],
          [1, 2000001154, 2586595328, 0, 2586648576, 631506, 631493, 2000609513, 36015302225, 860536832, 0, 860614656, 210111, 210092, 1999948006, 25290242280],
          [1, 2999999420, 3859476480, 0, 3859574784, 942279, 942255, 3000797939, 53930991917, 1283543040, 0, 1283575808, 313373, 313365, 2999954058, 38118478892],
          [1, 4000053596, 5141098496, 0, 5141168128, 1255168, 1255151, 4001044343, 71667482948, 1709035520, 0, 1709096960, 417260, 417245, 4000009493, 51118387249],
          [1, 5000048193, 6431453184, 0, 6431526912, 1570197, 1570179, 5001249425, 89621839555, 2140831744, 0, 2140889088, 522678, 522664, 5000022758, 63850814542],
          [1, 999356363, 1310584832, 0, 1310654464, 319984, 319967, 999355900, 18428824122, 436121600, 0, 436183040, 106490, 106475, 999423546, 12148739904],
          [1, 1999361060, 2630619136, 0, 2630701056, 642261, 642241, 1998871129, 36983483350, 875077632, 0, 875126784, 213654, 213642, 1998856386, 24183929582],
          [1, 2999493650, 3910578176, 0, 3910664192, 954752, 954731, 2998852338, 55164766003, 1300946944, 0, 1300992000, 317625, 317614, 2999000221, 36648129862]]
    _LayoutStats(t, env, ls)

def testFlexLayoutStatsStraight(t, env):
    """These stats are the same as the reset ones, but have been massaged
    to keep the server from detecting the reset. I.e., the client
    has not lost it all!

    FLAGS: flex layoutstats
    CODE: FFLS3
    """

    ls = [[1, 999825140, 756789248, 0, 756834304, 184774, 184763, 999791161, 9058469753, 252579840, 0, 252665856, 61686, 61665, 999820527, 22465740306],
          [1, 1999826975, 1527537664, 0, 1527566336, 372941, 372934, 1999742808, 18361075475, 508502016, 0, 508604416, 124171, 124146, 1999819571, 44691205162],
          [1, 2999957068, 2331115520, 0, 2331136000, 569125, 569120, 2999834431, 27615725838, 775569408, 0, 775680000, 189375, 189348, 2999939793, 66937095240],
          [1, 4000100924, 3142483968, 0, 3142529024, 767219, 767208, 3999950900, 36730403297, 1044996096, 0, 1045082112, 255147, 255126, 4000082197, 89344219014],
          [1, 5000104307, 3969384448, 0, 3969413120, 969095, 969088, 4999946963, 45850741352, 1320456192, 0, 1320542208, 322398, 322377, 5000077252, 111746260417],
          [1, 6000110131, 4873195520, 0, 4873248768, 1189758, 1189745, 5999946302, 55242979748, 1620467712, 0, 1620545536, 395641, 395622, 6000066305, 133793765932],
          [1, 7000114038, 5816430592, 0, 5816467456, 1420036, 1420027, 6999718858, 65281785171, 1935175680, 0, 1935269888, 472478, 472455, 6999944738, 155115199505],
          [1, 7999930387, 7282450432, 0, 7282565120, 1777970, 1777942, 7999838724, 83757851535, 2422800384, 0, 2422947840, 591540, 591504, 7999807387, 167063278303],
          [1, 9000080948, 8745824256, 0, 8745967616, 2135246, 2135211, 8999849868, 102247413671, 2909380608, 0, 2909499392, 710327, 710298, 8999864560, 179052537252],
          [1, 10000123265, 10061635584, 0, 10061713408, 2456473, 2456454, 10000094991, 120320393099, 3347156992, 0, 3347341312, 817222, 817177, 9999720550, 191619434141],
          [1, 11000122407, 11362164736, 0, 11362275328, 2773993, 2773966, 11000337846, 138440349632, 3779543040, 0, 3779670016, 922771, 922740, 10999723698, 204123483815],
          [1, 12000115398, 12640329728, 0, 12640501760, 3086060, 3086018, 12000744124, 156490343228, 4205420544, 0, 4205617152, 1026762, 1026714, 11999746492, 216750225507],
          [1, 13000123561, 13948760064, 0, 13948923904, 3405499, 3405459, 13000947360, 174455651858, 4640079872, 0, 4640284672, 1132882, 1132832, 12999671705, 229413726095],
          [1, 14000121827, 15221641216, 0, 15221850112, 3716272, 3716221, 14001135785, 192371341550, 5063086080, 0, 5063245824, 1236144, 1236105, 13999677756, 242241962708],
          [1, 15000176003, 16503263232, 0, 16503443456, 4029161, 4029117, 15001382189, 210107832581, 5488578560, 0, 5488766976, 1340031, 1339985, 14999733191, 255241871064],
          [1, 16000170601, 17793617920, 0, 17793802240, 4344190, 4344145, 16001587271, 228062189188, 5920374784, 0, 5920559104, 1445449, 1445404, 15999746456, 267974298357],
          [1, 16999526964, 19104202752, 0, 19104456704, 4664174, 4664112, 17000943172, 246491013310, 6356496384, 0, 6356742144, 1551939, 1551879, 16999170003, 280123038261],
          [1, 17999531661, 20424237056, 0, 20424503296, 4986451, 4986386, 18000458400, 265045672538, 6795452416, 0, 6795685888, 1659103, 1659046, 17998602842, 292158227939],
          [1, 18999664251, 21704196096, 0, 21704466432, 5298942, 5298876, 19000439609, 283226955191, 7221321728, 0, 7221551104, 1763074, 1763018, 18998746678, 304622428220]]
    _LayoutStats(t, env, ls)

def testFlexLayoutStatsOverflow(t, env):
    """These layoutstats are a write intensive work load in which eventually one stat takes
    twice longer than the collection period.

    FLAGS: flex layoutstats
    CODE: FFLS4
    """

    ls = [[3, 3944883337, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 96468992, 10292, 10240, 3801297886, 19149682227252],
          [2, 6103624106, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 2402213888, 15847, 11881, 4494091156, 19481034613938],
          [2, 8273170067, 0, 0, 0, 0, 0, 0, 0, 41943040, 0, 2406907904, 15924, 11881, 4494091156, 19481034613938],
          [2, 10417402024, 0, 0, 0, 0, 0, 0, 0, 896532480, 0, 2946293760, 16847, 15969, 10055956635, 39298178596027],
          [2, 12560319963, 0, 0, 0, 0, 0, 0, 0, 896532480, 0, 3196473344, 18335, 15969, 10055956635, 39298178596027],
          [2, 14707068057, 0, 0, 0, 0, 0, 0, 0, 1808183296, 0, 4038545408, 20452, 19074, 13207903465, 44308475505328],
          [2, 16850193026, 0, 0, 0, 0, 0, 0, 0, 2587693056, 0, 4486782976, 22613, 19935, 16707249318, 47391414257701],
          [2, 19002460651, 0, 0, 0, 0, 0, 0, 0, 2587693056, 0, 4830961664, 23306, 22169, 16857855539, 50539774920845],
          [2, 21147303879, 0, 0, 0, 0, 0, 0, 0, 4132970496, 0, 5960671232, 29861, 26094, 20875445137, 55294954662308],
          [2, 23294079462, 0, 0, 0, 0, 0, 0, 0, 5614419968, 0, 7550558208, 40590, 39198, 22734154388, 64805011122198],
          [2, 25438252925, 0, 0, 0, 0, 0, 0, 0, 5614419968, 0, 7838756864, 41554, 39198, 22734154388, 64805011122198],
          [2, 27583065244, 0, 0, 0, 0, 0, 0, 0, 6428528640, 0, 8151494656, 43497, 42179, 27069485673, 73878230841436],
          [2, 29726089447, 0, 0, 0, 0, 0, 0, 0, 7284596736, 0, 8656367616, 47929, 43079, 29583282616, 76105970720785],
          [2, 31868949042, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9539055616, 58212, 53705, 31726209646, 90881186233885],
          [2, 34011875329, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9763426304, 62673, 57863, 31927335875, 92921547616160],
          [2, 36167894607, 0, 0, 0, 0, 0, 0, 0, 7944978432, 0, 9860571136, 65509, 57863, 31927335875, 92921547616160],
          [2, 38312188125, 0, 0, 0, 0, 0, 0, 0, 8729772032, 0, 10523738112, 71014, 65222, 38166438595, 121977090143760],
          [2, 40826809525, 0, 0, 0, 0, 0, 0, 0, 9522692096, 0, 10779361280, 72612, 66965, 40683877463, 128092889045628],
          [4, 45509840027, 0, 0, 0, 0, 0, 0, 0, 9522692096, 0, 10779361280, 72613, 72611, 45366126519, 160032830605661],
          [2, 47678212738, 0, 0, 0, 0, 0, 0, 0, 10788278272, 0, 10788802560, 74918, 74790, 47461923670, 160243311612070],
          [2, 49821374036, 0, 0, 0, 0, 0, 0, 0, 10801360896, 0, 10801885184, 78112, 77984, 49605086464, 160524033872308],
          [1, 51716383249, 0, 0, 0, 0, 0, 0, 0, 10812923904, 0, 10814496768, 81191, 80935, 51590652837, 160755578106599],
          [2, 53859490747, 0, 0, 0, 0, 0, 0, 0, 10836291584, 0, 10837864448, 86896, 86640, 53733759520, 161028352155276],
          [2, 56003923563, 0, 0, 0, 0, 0, 0, 0, 10852364288, 0, 10853937152, 90820, 90564, 55878188780, 161301881961592],
          [2, 58147811871, 0, 0, 0, 0, 0, 0, 0, 10864914432, 0, 10866487296, 93884, 93628, 58022079204, 161574823883315]]
    _LayoutStats(t, env, ls)

def layoutget_return(sess, fh, open_stateid, allowed_errors=NFS4_OK,
                     layout_iomode=LAYOUTIOMODE4_RW, layout_error=None,
                     layout_error_op=OP_WRITE):
    """
    Perform LAYOUTGET and LAYOUTRETURN
    """

    # Get layout
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_FLEX_FILES, layout_iomode,
                        0, NFS4_MAXFILELEN, 4196, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res, allowed_errors)
    if res.status != NFS4_OK:
        return [res] # We can't return the layout without a stateid!
    layout_stateid = res.resarray[-1].logr_stateid

    # Return layout
    if not layout_error:  # Return regular layout
        ops = [op.putfh(fh),
               op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                               layoutreturn4(LAYOUTRETURN4_FILE,
                                             layoutreturn_file4(0, NFS4_MAXFILELEN,
                                                                layout_stateid, empty_p.get_buffer())))]
    else:  # Return layout with error
        # Get device id
        locb = res.resarray[-1].logr_layout[0].lo_content.loc_body
        p = FlexUnpacker(locb)
        layout = p.unpack_ff_layout4()
        p.done()

        deviceid = layout.ffl_mirrors[0].ffm_data_servers[0].ffds_deviceid
        deverr = device_error4(deviceid, layout_error, layout_error_op)
        ffioerr = ff_ioerr4(0, NFS4_MAXFILELEN, layout_stateid, [deverr])
        fflr = ff_layoutreturn4([ffioerr], [])

        p = FlexPacker()
        p.pack_ff_layoutreturn4(fflr)

        ops = [op.putfh(fh),
               op.layoutreturn(False, LAYOUT4_FLEX_FILES, LAYOUTIOMODE4_ANY,
                               layoutreturn4(LAYOUTRETURN4_FILE,
                                             layoutreturn_file4(0, NFS4_MAXFILELEN,
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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ, NFS4ERR_NXIO, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_NXIO], LAYOUTIOMODE4_READ)

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_NXIO, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_NXIO])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ, NFS4ERR_STALE, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_STALE])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_STALE, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_STALE])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ, NFS4ERR_IO, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_IO])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_IO, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_IO])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ, NFS4ERR_SERVERFAULT, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_SERVERFAULT])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_SERVERFAULT, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_SERVERFAULT])

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnNospcRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_NOSPC on READ

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_NOSPC, OP_WRITE)

    # Verify error code propagation
    # Unlike with a WRITE, we should see no error
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnNospcWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_NOSPC on WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORNOSPCWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_NOSPC, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_NOSPC], LAYOUTIOMODE4_RW)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnFbigRead(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_FBIG on READ

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_FBIG, OP_WRITE)

    # Verify error code propagation
    # Unlike with a WRITE, we should see no error
    layoutget_return(sess, fh, open_stateid, NFS4_OK)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturnFbigWrite(t, env):
    """
    Send LAYOUTRETURN with NFS4ERR_FBIG on WRITE

    FLAGS: flex layoutreturn
    CODE: FFLORFBIGWRITE
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    # Return layout with error
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_FBIG, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_FBIG])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ,
                     NFS4ERR_ACCESS, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_ACCESS])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW,
                     NFS4ERR_ACCESS, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_ACCESS])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_READ, NFS4ERR_DELAY, OP_READ)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY])

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
    layoutget_return(sess, fh, open_stateid, NFS4_OK, LAYOUTIOMODE4_RW, NFS4ERR_DELAY, OP_WRITE)

    # Verify error code propagation
    layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY])

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)

def testFlexLayoutReturn100(t, env):
    """
    Perform LAYOUTGET and LAYOUTRETURN 100 times with error being returned periodically

    FLAGS: flex layoutreturn
    CODE: FFLOR100
    """
    name = env.testname(t)
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    count = 100  # Repeat LAYOUTGET/LAYOUTRETURN count times
    layout_error_ratio = 10  # Send an error every layout_error_ratio layout returns

    # Create the file
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid

    for i in range(count):
        layout_error = None if i % layout_error_ratio else NFS4ERR_ACCESS
        layoutget_return(sess, fh, open_stateid, layout_error=layout_error)

        # Verify error code propagation
        if layout_error:
            layoutget_return(sess, fh, open_stateid, [NFS4_OK, NFS4ERR_DELAY, layout_error])
        else:
            layoutget_return(sess, fh, open_stateid, NFS4_OK)

    # Close file
    res = close_file(sess, fh, stateid=open_stateid)
    check(res)
