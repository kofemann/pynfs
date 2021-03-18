from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, use_obj, write_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()

def testZeroLengthCopy(t, env):
    """test that zero-length copy copies to EOF

    FLAGS: copy
    CODE: COPY5
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    data = b"write test data"
    res = write_file(sess1, fh, data, 0, stateid)
    res = create_file(sess1, env.testname(t)+b"_copy")
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    copy = [op.putfh(fh), op.savefh(), op.putfh(fh2),
            op.copy(stateid, stateid2, 0, 0, 0, 0, 1, [])]
    res = sess1.compound(copy)
    check(res)
    l = res.resarray[-1].cr_response.wr_count
    if l != len(data):
        fail("Copy to end of %d-byte file copied %d bytes" % (len(data), l))
