from xdrdef.nfs4_const import *
import nfs_ops
op = nfs_ops.NFS4ops()
from environment import check, fail, get_invalid_utf8strings
from xdrdef.nfs4_type import *
from rpc import RPCAcceptError, GARBAGE_ARGS, RPCTimeout
from nfs4lib import NFS4Error, hash_oids, encrypt_oids, FancyNFS4Packer

def _simple_ops(t, env):
    """Produce a simple, valid ops sequence"""
    owner = client_owner4(env.c1.verifier, env.testname(t))
    protect = state_protect4_a(SP4_NONE)
    return [op.exchange_id(owner, EXCHGID4_FLAG_USE_NON_PNFS, protect,
                           [env.c1.impl_id])]

def testZeroOps(t, env):
    """COMPOUND without operations should return NFS4_OK

    FLAGS: compound all
    CODE: COMP1
    """
    c = env.c1
    res = c.compound([])
    check(res)

def testGoodTag(t, env):
    """COMPOUND with tag

    FLAGS: compound all
    CODE: COMP2
    """
    c = env.c1
    tag = 'tag test'
    res = c.compound(_simple_ops(t, env), tag=tag)
    check(res)
    if res.tag != tag:
        t.fail("Returned tag '%s' does not equal sent tag '%s'" %
               (res.tag, tag))

def testBadTags(t, env):
    """COMPOUND with invalid utf8 tags

    FLAGS: compound utf8 ganesha
    CODE: COMP3
    """
    c = env.c1
    for tag in get_invalid_utf8strings():
        res = c.compound([], tag=tag)
        check(res, NFS4ERR_INVAL, "Compound with invalid utf8 tag %s" %
              repr(tag))

def testInvalidMinor(t, env):
    """COMPOUND with invalid minor version returns NFS4ERR_MINOR_VERS_MISMATCH

    FLAGS: compound all
    CODE: COMP4a
    """
    c = env.c1
    res = c.compound(_simple_ops(t, env), version=50)
    check(res, NFS4ERR_MINOR_VERS_MISMATCH,
          "COMPOUND with invalid minor version")
    if res.resarray:
        t.fail("Nonempty result array after NFS4ERR_MINOR_VERS_MISMATCH")

def testInvalidMinor2(t, env):
    """COMPOUND with invalid minor version returns NFS4ERR_MINOR_VERS_MISMATCH

    even if using illegal opcode (rfc 5661 p. 399)

    FLAGS: compound all
    CODE: COMP4b
    """
    c = env.c1
    res = c.compound([op.illegal()], version=50)
    check(res, NFS4ERR_MINOR_VERS_MISMATCH)
    if res.resarray:
        t.fail("Nonempty result array after NFS4ERR_MINOR_VERS_MISMATCH")

def testUndefined(t, env):
    """Send an Illegal op code

    draft23, section 15.1.3.4:
    "Where an illegal value appears and the replier pre-parses all operations
    for a Compound procedure before doing any operation execution, an
    RPC-level XDR error may be returned in this case."

    draft23, section 16.2.3, line 21546:
    A server may decode the request with a one pass XDR decode.  "If there is
    an XDR decoding error in this case, the RPC XDR decode error would be
    returned"

    draft23, section 16.2.3, line 21590:
    After recieving an ILLEGAL or unknown op code, "the server's response will
    encode the opcode OP_ILLEGAL rather than the illegal opcode of the request,
    and "The status field in the ILLEGAL return results will set to
    NFS4ERR_OP_ILLEGAL"

    If "will" in section 16.2.3 is synonymous with SHALL as described in RFC
    2119, this constitutes a contradiction.  If "will" means something else....

    This test conforms with section 15.1.3.4  and section 16.2.3, line 21546.

    FLAGS: compound all
    CODE: COMP5
    """
    c = env.c1
    class CustomPacker(FancyNFS4Packer):
        def pack_nfs_argop4(self, data):
            try:
                FancyNFS4Packer.pack_nfs_argop4(self, data)
            except:
                # If it fails, try to just pack the opcode with void args
                self.pack_uint32_t(data.argop)
    for i in [0, 1, 2, 72, OP_ILLEGAL]:
        a = nfs_argop4(argop = i)
        try:
            res = c.compound([a], packer=CustomPacker)
            check(res, NFS4ERR_OP_ILLEGAL)
            if res.resarray[-1].resop != OP_ILLEGAL:
                t.fail('Server echoed invalid opcode: Should return OP_ILLEGAL')
        except RPCAcceptError, e:
            if e.stat == GARBAGE_ARGS:
                pass
            else:
                t.fail('RPCError')
