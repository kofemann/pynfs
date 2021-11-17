from .base import SecFlavor, SecError
from rpc.rpc_const import RPCSEC_GSS
from rpc.rpc_type import opaque_auth
from .gss_const import *
from . import gss_pack
import gss_type
import gssapi
import threading

WINDOWSIZE = 10 # STUB, curently just a completely random number

#XXX eventually, krb stuff must be separated from gss code
krb5_minor_codes = {
    0 : "KDC_ERR_NONE",
    1 : "KDC_ERR_NAME_EXP",
    2 : "KDC_ERR_SERVICE_EXP",
    3 : "KDC_ERR_BAD_PVNO",
    4 : "KDC_ERR_C_OLD_MAST_KVNO",
    5 : "KDC_ERR_S_OLD_MAST_KVNO",
    6 : "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7 : "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    8 : "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
    9 : "KDC_ERR_NULL_KEY",
    10 : "KDC_ERR_CANNOT_POSTDATE",
    11 : "KDC_ERR_NEVER_VALID",
    12 : "KDC_ERR_POLICY",
    13 : "KDC_ERR_BADOPTION",
    14 : "KDC_ERR_ETYPE_NOSUPP",
    15 : "KDC_ERR_SUMTYPE_NOSUPP",
    16 : "KDC_ERR_PADATA_TYPE_NOSUPP",
    17 : "KDC_ERR_TRTYPE_NOSUPP",
    18 : "KDC_ERR_CLIENT_REVOKED",
    19 : "KDC_ERR_SERVICE_REVOKED",
    20 : "KDC_ERR_TGT_REVOKED",
    21 : "KDC_ERR_CLIENT_NOTYET",
    22 : "KDC_ERR_SERVICE_NOTYET",
    23 : "KDC_ERR_KEY_EXPIRED",
    24 : "KDC_ERR_PREAUTH_FAILED",
    25 : "KDC_ERR_PREAUTH_REQUIRED",
    26 : "KDC_ERR_SERVER_NOMATCH",
    27 : "KDC_ERR_MUST_USE_USER2USER",
    31 : "KRB_AP_ERR_BAD_INTEGRITY",
    32 : "KRB_AP_ERR_TKT_EXPIRED",
    33 : "KRB_AP_ERR_TKT_NYV",
    34 : "KRB_AP_ERR_REPEAT",
    35 : "KRB_AP_ERR_NOT_US",
    36 : "KRB_AP_ERR_BADMATCH",
    37 : "KRB_AP_ERR_SKEW",
    38 : "KRB_AP_ERR_BADADDR",
    39 : "KRB_AP_ERR_BADVERSION",
    40 : "KRB_AP_ERR_MSG_TYPE",
    41 : "KRB_AP_ERR_MODIFIED",
    42 : "KRB_AP_ERR_BADORDER",
    44 : "KRB_AP_ERR_BADKEYVER",
    45 : "KRB_AP_ERR_NOKEY",
    46 : "KRB_AP_ERR_MUT_FAIL",
    47 : "KRB_AP_ERR_BADDIRECTION",
    48 : "KRB_AP_ERR_METHOD",
    49 : "KRB_AP_ERR_BADSEQ",
    50 : "KRB_AP_ERR_INAPP_CKSUM",
    60 : "KRB_ERR_GENERIC",
    61 : "KRB_ERR_FIELD_TOOLONG",
}
    
def show_minor(m):
    """Return string corresponding to minor code"""
    # XXX krb specific currently
    default = "UNKNOWN_MINOR_CODE_%i" % m
    return krb5_minor_codes.get(m, default)
    
def show_major(m):
    """Return string corresponding to major code"""
    if m == 0:
        return gss_major_codes[0]
    call = m & 0xff000000
    routine = m & 0xff0000
    supp = m & 0xffff
    out = []
    if call:
        out.append(gss_major_codes[call])
    if routine:
        out.append(gss_major_codes[routine])
    if supp:
        out.append(gss_major_codes[supp])
    return ' | '.join(out)

def hint_string(d):
    """Return a hint regarding how to deal with error, or None"""
    hints = {(851968, 13) : "Do you have permission to read the krb5.* files?"}
    return hints.get((d["major"], d["minor"]), None)

class SecAuthGss(SecFlavor):
    krb5_oid = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
    def __init__(self, service=rpc_gss_svc_none):
        t = threading.currentThread()
        self.lock = threading.Lock()
        self.gss_seq_num = 0
        self.init = 1
        self.service = service
        self._packer = {t : gss_pack.GSSPacker()}
        self._unpacker = {t : gss_pack.GSSUnpacker('')}

    def getpacker(self):
        t = threading.currentThread()
        self.lock.acquire()
        if t in self._packer:
            out = self._packer[t]
        else:
            out = self._packer[t] = gss_pack.GSSPacker()
            self._unpacker[t] = gss_pack.GSSUnpacker('')
        self.lock.release()
        return out

    def getunpacker(self):
        t = threading.currentThread()
        self.lock.acquire()
        if t in self._unpacker:
            out = self._unpacker[t]
        else:
            self._packer[t] = gss_pack.GSSPacker()
            out = self._unpacker[t] = gss_pack.GSSUnpacker('')
        self.lock.release()
        return out

    def initialize(self, client): # Note this is not thread safe
        """Set seq_num, init, handle, and context"""
        self.gss_seq_num = 0
        name = gssapi.Name("nfs@%s" % client.remotehost, gssapi.NameType.hostbased_service)
        # We need to send NULLPROCs with token from SecurityContext
        good_major = [GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED]
        self.init = 1
        input_token = None

        # RFC2203 5.2.2.  Context Creation Requests
        # When GSS_Init_sec_context() is called, the parameters
        # replay_det_req_flag and sequence_req_flag must be turned off.

        # Note - by default, out_of_sequence_detection flag (sequence_req_flag) is used by gssapi.init_sec_context()
        # and we have 'An expected per-message token was not received' error (GSS_S_GAP_TOKEN).
        # To prevent this, we need to use default flags without out_of_sequence_detection bit.
        flags = gssapi.IntEnumFlagSet(gssapi.RequirementFlag, [gssapi.RequirementFlag.mutual_authentication])
        context = gssapi.SecurityContext(name=name, flags=flags)
        while True:
            # note - gssapi will raise an exception here automatically in case of failure
            output_token = context.step(input_token)
            if context.complete:
                break
            p = self.getpacker()
            p.reset()
            p.pack_opaque(output_token)
            data = p.get_buffer()
            reply = client.call(0, data)
            up = self.getunpacker()
            up.reset(reply)
            res = up.unpack_rpc_gss_init_res()
            up.done()
            reply_major = res.gss_major
            if reply_major not in good_major:
                raise SecError("Server returned: %s" % \
                    show_major(reply_major))
            self.init = 2
            input_token = res.gss_token
        self.gss_context = context
        self.gss_handle = res.handle
        self.init = 0
        
    def make_cred(self):
        """Credential sent with each RPC call"""
        if self.init == 1: # first call in context creation
            cred = self._make_cred_gss(b'', rpc_gss_svc_none, RPCSEC_GSS_INIT)
        elif self.init > 1: # subsequent calls in context creation
            cred = self._make_cred_gss('', rpc_gss_svc_none,
                                  RPCSEC_GSS_CONTINUE_INIT)
        else: # data transfer calls
            self.lock.acquire()
            self.gss_seq_num += 1 # FRED - check for overflow
            self.lock.release()
            cred = self._make_cred_gss(self.gss_handle, self.service,
                                       seq=self.gss_seq_num)
        return opaque_auth(RPCSEC_GSS, cred)

    def read_cred(self, data):
        p = self.getunpacker()
        p.reset(data)
        out = p.unpack_rpc_gss_cred_t()
        p.done()
        return out.switch

    def handle_proc(self, body, data):
        import rpc
        if body.gss_proc == RPCSEC_GSS_INIT:
            p = self.getunpacker()
            p.reset(data)
            token = p.unpack_opaque()
            p.done()
            d = gssapi.acceptSecContext(token, body.handle)
            if d["major"] == GSS_S_COMPLETE:
                print("SUCCESS!")
                class C(object):
                    pass
                out = C()
                out.handle = gssapi.ptr2str(d['context'])
                out.gss_major = d['major']
                out.gss_minor = d['minor']
                out.seq_window = WINDOWSIZE
                out.gss_token = d['token']
                p = self.getpacker()
                p.reset()
                p.pack_rpc_gss_init_res(out)
                out = p.get_buffer()
                self.init = 0
                self.gss_context = d['context']
                return rpc.SUCCESS, out
            else:
                out = hint_string(d)
                if out is not None:
                    print(out)
                return rpc.GARBAGE_ARGS, ''
        else:
            # Stub
            print("Unable to handle gss_proc==%i" % body.gss_proc)
            return rpc.GARBAGE_ARGS, ''
    def make_verf(self, data):
        """Verifier sent with each RPC call

        'data' is packed header upto and including cred
        """
        if self.init:
            return self._none
        else:
            token = self.gss_context.get_signature(data)
            return opaque_auth(RPCSEC_GSS, token)
        
    def _make_cred_gss(self, handle, service, gss_proc=RPCSEC_GSS_DATA, seq=0):
        data = gss_type.rpc_gss_cred_vers_1_t(gss_proc, seq, service, handle)
        cred = gss_type.rpc_gss_cred_t(RPCSEC_GSS_VERS_1, data)
        p = self.getpacker()
        p.reset()
        p.pack_rpc_gss_cred_t(cred)
        return p.get_buffer()

    def secure_data(self, data, cred):
        """Add security info/encryption to procedure arg/res"""
        gss_cred = self._gss_cred_from_opaque_auth(cred)
        if gss_cred.service == rpc_gss_svc_none or \
               gss_cred.gss_proc != RPCSEC_GSS_DATA:
            pass
        elif gss_cred.service == rpc_gss_svc_integrity:
            # data = opaque[gss_seq_num+data] + opaque[checksum]
            p = self.getpacker()
            p.reset()
            p.pack_uint(gss_cred.seq_num)
            data = p.get_buffer() + data
            token = self.gss_context.get_signature(data)
            p.reset()
            p.pack_opaque(data)
            p.pack_opaque(token)
            data = p.get_buffer()
        elif gss_cred.service == rpc_gss_svc_privacy:
            # data = opaque[wrap([gss_seq_num+data])]
            p = self.getpacker()
            p.reset()
            p.pack_uint(gss_cred.seq_num)
            data = p.get_buffer() + data
            wrap_data = self.gss_context.wrap(data, encrypt=True)
            p.reset()
            p.pack_opaque(wrap_data.message)
            data = p.get_buffer()
        else:
            # Not really necessary, should have already raised XDRError
            raise SecError("Unknown service %i for RPCSEC_GSS" % gss_cred.service)
        return data

    def unsecure_data(self, data, cred):
        """Remove gss cruft from procedure arg/res"""
        gss_cred = self._gss_cred_from_opaque_auth(cred)
        if gss_cred.service == rpc_gss_svc_none or \
               gss_cred.gss_proc != RPCSEC_GSS_DATA:
            pass
        elif gss_cred.service == rpc_gss_svc_integrity:
            # data = opaque[gss_seq_num+data] + opaque[checksum]
            p = self.getunpacker()
            p.reset(data)
            data = p.unpack_opaque()
            checksum = p.unpack_opaque()
            p.done()
            qop = self.gss_context.verify_signature(data, checksum)
            p.reset(data)
            seqnum = p.unpack_uint()
            if seqnum != gss_cred.seq_num:
                raise SecError(\
                      "Mismatched seqnum in reply: got %i, expected %i" % \
                      (seqnum, gss_cred.seq_num))
            data = p.get_buffer()[p.get_position():]
        elif gss_cred.service == rpc_gss_svc_privacy:
            # data = opaque[wrap([gss_seq_num+data])]
            p = self.getunpacker()
            p.reset(data)
            data = p.unpack_opaque()
            p.done()
            data, encrypted, qop = self.gss_context.unwrap(data)
            p.reset(data)
            seqnum = p.unpack_uint()
            if seqnum != gss_cred.seq_num:
                raise SecError(\
                      "Mismatched seqnum in reply: got %i, expected %i" % \
                      (seqnum, self.gss_cred.seq_num))
            data = p.get_buffer()[p.get_position():]
        else:
            # Not really necessary, should have already raised XDRError
            raise SecError("Unknown service %i for RPCSEC_GSS" % gss_cred.service)
        return data

    def _gss_cred_from_opaque_auth(self, auth):
        p = self.getunpacker()
        data = auth.body
        p.reset(data)
        cred = p.unpack_rpc_gss_cred_t()
        p.done
        return cred.switch # return version switch branch
        
    def make_reply_verf(self, cred, stat):
        cred = self._gss_cred_from_opaque_auth(cred)
        i = None
        if stat:
            # Return trivial verf on error
            return self._none
        elif cred.gss_proc != RPCSEC_GSS_DATA:
            # STUB - init requires getMIC(seq_window)
            i = WINDOWSIZE
        else:
            # Else return getMIC(cred.seq_num)
            i = cred.seq_num
        p = self.getpacker()
        p.reset()
        p.pack_uint(i)
        d = gssapi.getMIC(self.gss_context, p.get_buffer())
        if d['major'] != gssapi.GSS_S_COMPLETE:
            raise SecError("gssapi.getMIC returned: %s" % \
                  show_major(d['major']))
        return opaque_auth(RPCSEC_GSS, d['token'])

    def check_verf(self, rverf, cred):
        """Raise error if there is a problem with reply verifier"""
        # STUB
        if rverf.flavor == 6 and hasattr(self, 'gss_context'):
            cred = self._gss_cred_from_opaque_auth(cred)
            p = self.getpacker()
            p.reset()
            p.pack_uint(cred.seq_num)
            qop = self.gss_context.verify_signature(p.get_buffer(), rverf.body)
            
        else:
            pass

