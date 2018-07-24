from base import SecFlavor, SecError
from rpc.rpc_const import RPCSEC_GSS
from rpc.rpc_type import opaque_auth
from gss_const import *
import gss_pack
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
        d = gssapi.importName("nfs@%s" % client.remotehost)
        if d['major'] != gssapi.GSS_S_COMPLETE:
            raise SecError("gssapi.importName returned: %s" % \
                  show_major(d['major']))
        name = d['name']
        # We need to send NULLPROCs with token from initSecContext
        good_major = [gssapi.GSS_S_COMPLETE, gssapi.GSS_S_CONTINUE_NEEDED]
        self.init = 1
        reply_token = None
        reply_major = ''
        context = None
        while True:
            d = gssapi.initSecContext(name, context, reply_token)
            major = d['major']
            context = d['context']
            if major not in good_major:
                raise SecError("gssapi.initSecContext returned: %s" % \
                      show_major(major))
            if (major == gssapi.GSS_S_CONTINUE_NEEDED) and \
                   (reply_major == gssapi.GSS_S_COMPLETE):
                raise SecError("Unexpected GSS_S_COMPLETE from server")
            token = d['token']
            if reply_major != gssapi.GSS_S_COMPLETE:
                # FRED - sec 5.2.2 of RFC 2203 mentions possibility that
                # no token is returned.  But then how get handle?
                p = self.getpacker()
                p.reset()
                p.pack_opaque(token)
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
                reply_token = res.gss_token
            if major == gssapi.GSS_S_COMPLETE:
                if reply_major != gssapi.GSS_S_COMPLETE:
                    raise SecError("Unexpected COMPLETE from client")
                break
        self.gss_context = context
        self.gss_handle = res.handle
        self.init = 0
        
    def make_cred(self):
        """Credential sent with each RPC call"""
        if self.init == 1: # first call in context creation
            cred = self._make_cred_gss('', rpc_gss_svc_none, RPCSEC_GSS_INIT)
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
            d = gssapi.getMIC(self.gss_context, data)
            major = d['major']
            if major != gssapi.GSS_S_COMPLETE:
                raise SecError("gssapi.getMIC returned: %s" % \
                      show_major(major))
            return opaque_auth(RPCSEC_GSS, d['token'])
        
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
            d = gssapi.getMIC(self.gss_context, data)
            if d['major'] != gssapi.GSS_S_COMPLETE:
                raise SecError("gssapi.getMIC returned: %s" % \
                      show_major(d['major']))
            p.reset()
            p.pack_opaque(data)
            p.pack_opaque(d['token'])
            data = p.get_buffer()
        elif gss_cred.service == rpc_gss_svc_privacy:
            # data = opaque[wrap([gss_seq_num+data])]
            p = self.getpacker()
            p.reset()
            p.pack_uint(gss_cred.seq_num)
            data = p.get_buffer() + data
            d = gssapi.wrap(self.gss_context, data)
            if d['major'] != gssapi.GSS_S_COMPLETE:
                raise SecError("gssapi.wrap returned: %s" % \
                      show_major(d['major']))
            p.reset()
            p.pack_opaque(d['msg'])
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
            d = gssapi.verifyMIC(self.gss_context, data, checksum)
            if d['major'] != gssapi.GSS_S_COMPLETE:
                raise SecError("gssapi.verifyMIC returned: %s" % \
                      show_major(d['major']))
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
            d = gssapi.unwrap(self.gss_context, data)
            if d['major'] != gssapi.GSS_S_COMPLETE:
                raise SecError("gssapi.unwrap returned %s" % \
                      show_major(d['major']))
            p.reset(d['msg'])
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
            d = gssapi.verifyMIC(self.gss_context, p.get_buffer(), rverf.body)
            #print("Verify(%i):"%cred.seq_num, show_major(d['major']), show_minor(d['minor']))
            
        else:
            pass

