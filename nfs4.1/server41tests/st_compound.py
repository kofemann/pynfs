from nfs4_const import *
import nfs4_ops as op
from environment import check, fail
from nfs4_type import *
from rpc import RPCAcceptError, GARBAGE_ARGS, RPCTimeout
from nfs4lib import NFS4Error, hash_oids, encrypt_oids, FancyNFS4Packer

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
    CODE: COMP1
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
