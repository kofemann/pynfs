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
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    lo_stateid = open_stateid

    for i in range(1000):
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_FLEX_FILES,
                            LAYOUTIOMODE4_READ if i%2  else LAYOUTIOMODE4_RW,
                            i * 8192, 8192, 8192, lo_stateid, 0xffff)]
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
