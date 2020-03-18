from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, do_getattrdict
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading


def testGetXattrAttribute(t, env):
    """Server with xattr support MUST support.

    FLAGS: xattr
    CODE: XATT1
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_SUPPORTED_ATTRS|1 <<FATTR4_XATTR_SUPPORT)])
    check(res)

    if FATTR4_SUPPORTED_ATTRS not in res.resarray[-1].obj_attributes:
        fail("Requested bitmap of supported attributes not provided")

    bitmask = res.resarray[-1].obj_attributes[FATTR4_SUPPORTED_ATTRS]
    if bitmask & (1 << FATTR4_XATTR_SUPPORT) == 0:
        fail("xattr_support is not included in the set of supported attributes")

    if FATTR4_XATTR_SUPPORT not in res.resarray[-1].obj_attributes:
        fail("Server doesn't support extended attributes")
