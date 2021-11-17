from xdrdef.nfs4_const import *
from .environment import check
from socket import timeout
import rpc.rpc as rpc
import rpc.rpcsec.gss_const as gss
from rpc.rpcsec.gss_type import rpc_gss_cred_t
import nfs_ops
op = nfs_ops.NFS4ops()

class BadGssHeader(object):
    """Screw up gss cred.

    Since we expect code to error out before dealing with secure/unsecure,
    have to make sure sending does *something* other than raise error.
    """

    def __init__(self, sec, bad_cred_funct):
        self.__sec = sec
        self._make_cred_gss = bad_cred_funct

    def make_cred(self):
        # We copy code so "self" refers here, not to self.__sec
        # There's got to be a better way to do this
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
        return rpc.opaque_auth(RPCSEC_GSS, cred)


    def secure_data(self, data, cred):
        return data

    def unsecure_data(self, data, cred):
        return data

    def __getattr__(self, attr):
        """Use overridden functions if they exist.

        Otherwise pass through to original security object.
        """
        return getattr(self.__sec, attr)
    
    
def _using_gss(t, env):
    if 'gss' not in rpc.supported:
        return False
    return isinstance(env.c1.security, rpc.supported['gss'])

def _using_service(t, env):
    return env.c1.security.service != gss.rpc_gss_svc_none

def _using_integrity(t, env):
    return env.c1.security.service == gss.rpc_gss_svc_integrity

def testBadGssSeqnum(t, env):
    """GSS: using an old gss_seq_num should cause dropped reply

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS1
    """
    c = env.c1
    res = c.compound([op.putrootfh()])
    check(res)
    success = False
    orig = c.security.gss_seq_num
    try:
        c.security.gss_seq_num -= 1
        try:
            res = c.compound([op.putrootfh()])
        except timeout:
            success = True
        except OSError:
            success = True
        if not success:
            t.fail("Using old gss_seq_num %i should cause dropped reply" %
                   (orig + 1))
    finally:
        c.security.gss_seq_num = orig
        
def testInconsistentGssSeqnum(t, env):
    """GSS: using inconsistent gss_seq_nums should return GARBAGE_ARGS in rpc accept_stat

    See RFC2203, end of sect 5.3.3.1

    FLAGS: gss all
    DEPEND: _using_gss _using_service
    CODE: GSS2
    """
    c = env.c1
    orig_funct = c.security.secure_data
    def bad_secure_data(data, cred):
        # Mess up gss_seq_num
        gss_cred = c.security._gss_cred_from_opaque_auth(cred)
        gss_cred.seq_num += 1
        p = c.security.getpacker()
        p.reset()
        p.pack_rpc_gss_cred_t(rpc_gss_cred_t(1, gss_cred))
        return orig_funct(data, rpc.opaque_auth(6, p.get_buffer()))

    try:
        c.security.secure_data = bad_secure_data
        err = None
        try:
            res = c.compound([op.putrootfh()])
            err = "operation erroneously suceeding"
        except rpc.RPCAcceptError as e:
            if e.stat == rpc.GARBAGE_ARGS:
                # This is correct response
                return
            err = str(e)
        except Exception as e:
            err = str(e)
        t.fail("Using inconsistent gss_seq_nums in header and body of message "
               "should return GARBAGE_ARGS, instead got %s" % err)
    finally:
        c.security.secure_data = orig_funct

def testBadVerfChecksum(t, env):
    """GSS: Bad verifier checksum should return RPCSEC_GSS_CREDPROBLEM

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS3
    """
    c = env.c1
    orig_funct = c.security.make_verf
    def bad_make_verf(data):
        # Mess up verifier
        return orig_funct(data + b"x")

    try:
        c.security.make_verf = bad_make_verf
        err = None
        try:
            res = c.compound([op.putrootfh()])
            err = "peration erroneously suceeding"
        except rpc.RPCDeniedError as e:
            if e.stat == rpc.AUTH_ERROR and e.astat == rpc.RPCSEC_GSS_CREDPROBLEM:
               # This is correct response
               return
            err = str(e)
        except Exception as e:
            err = str(e)
        t.fail("Using bad verifier checksum in header "
               "should return RPCSEC_GSS_CREDPROBLEM, instead got %s" % err)
    finally:
        c.security.make_verf = orig_funct

def testBadDataChecksum(t, env):
    """GSS: Bad data checksum should return GARBAGE_ARGS

    See RFC2203 sect 5.3.3.4.2

    FLAGS: gss all
    DEPEND: _using_gss _using_integrity
    CODE: GSS4
    """
    c = env.c1
    orig_funct = c.security.secure_data
    def bad_secure_data(data, seqnum):
        # Mess up checksum
        data = orig_funct(data, seqnum)
        if data[-4]:
            tail = b'\x00' + data[-3:]
        else:
            tail = b'\x01' + data[-3:]
        return data[:-4] + tail

    try:
        c.security.secure_data = bad_secure_data
        err = None
        try:
            res = c.compound([op.putrootfh()])
            err = "operation erroneously suceeding"
        except rpc.RPCAcceptError as e:
            if e.stat == rpc.GARBAGE_ARGS:
                # This is correct response
                return
            err = str(e)
        except Exception as e:
            err = str(e)
        t.fail("Using bad data checksum for body of message "
               "should return GARBAGE_ARGS, instead got %s" % err)
    finally:
        c.security.secure_data = orig_funct

def testBadVersion(t, env):
    """GSS: bad version number should return AUTH_BADCRED

    See RFC2203 end of sect 5.3.3.3

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS5
    """
    c = env.c1
    orig = c.security
    def bad_version(handle, service, gss_proc=0, seq=0):
        # Mess up version in credential
        p = c.security.getpacker()
        p.reset()
        p.pack_uint(version)
        p.pack_uint(gss_proc)
        p.pack_uint(seq)
        p.pack_uint(service)
        p.pack_opaque(handle)
        return p.get_buffer()

    try:
        c.security = BadGssHeader(orig, bad_version)
        bad_versions = [0, 2, 3, 1024]
        for version in bad_versions:
            err = None
            try:
                res = c.compound([op.putrootfh()])
                err = "operation erroneously suceeding"
            except rpc.RPCDeniedError as e:
                if e.stat == rpc.AUTH_ERROR and e.astat == rpc.AUTH_BADCRED:
                    # This is correct response
                    pass
                else:
                    err = str(e)
            except Exception as e:
                err = str(e)
            if err is not None:
                t.fail("Using bad gss version number %i "
                       "should return AUTH_BADCRED, instead got %s" %
                       (version, err))
    finally:
        c.security = orig

def testHighSeqNum(t, env):
    """GSS: a seq_num over MAXSEQ should return RPCSEC_GSS_CTXPROBLEM

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS6
    """
    c = env.c1
    orig_seq = c.security.gss_seq_num
    try:
        c.security.gss_seq_num = gss.MAXSEQ + 1
        err = None
        try:
            res = c.compound([op.putrootfh()])
            err = "operation erroneously suceeding"
        except rpc.RPCDeniedError as e:
            if e.stat == rpc.AUTH_ERROR and e.astat == rpc.RPCSEC_GSS_CTXPROBLEM:
                # This is correct response
                return
        except Exception as e:
            err = str(e)
        t.fail("Using gss_seq_num over MAXSEQ "
               "should return RPCSEC_GSS_CTXPROBLEM, instead got %s" % err)
    finally:
        c.security.gss_seq_num = orig_seq

def testBadProcedure(t, env):
    """GSS: bad procedure number should return AUTH_BADCRED

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS7
    """
    c = env.c1
    orig = c.security
    def bad_proc(handle, service, gss_proc=0, seq=0):
        # Mess up procedure number in credential
        p = c.security.getpacker()
        p.reset()
        p.pack_uint(1)
        p.pack_uint(proc)
        p.pack_uint(seq)
        p.pack_uint(service)
        p.pack_opaque(handle)
        return p.get_buffer()

    try:
        c.security = BadGssHeader(orig, bad_proc)
        err = None
        bad_procss = [4, 5, 1024]
        for proc in bad_procss:
            try:
                res = c.compound([op.putrootfh()])
                err = "operation erroneously suceeding"
            except rpc.RPCDeniedError as e:
                if e.stat == rpc.AUTH_ERROR and e.astat == rpc.AUTH_BADCRED:
                    # This is correct response
                    pass
                else:
                    err = str(e)
            except Exception as e:
                err = str(e)
            if err is not None:
                t.fail("Using bad gss procedure number %i "
                       "should return AUTH_BADCRED, instead got %s" %
                       (proc, err))
    finally:
        c.security = orig

def testBadService(t, env):
    """GSS: bad service number should return AUTH_BADCRED

    See RFC2203 end of sect 5.3.3.3

    FLAGS: gss all
    DEPEND: _using_gss
    CODE: GSS8
    """
    c = env.c1
    orig = c.security
    def bad_service(handle, ignore_service, gss_proc=0, seq=0):
        # Mess up service number in credential
        p = c.security.getpacker()
        p.reset()
        p.pack_uint(1)
        p.pack_uint(gss_proc)
        p.pack_uint(seq)
        p.pack_uint(service)
        p.pack_opaque(handle)
        return p.get_buffer()

    try:
        c.security = BadGssHeader(orig, bad_service)
        err = None
        bad_services = [0, 4, 5, 1024]
        for service in bad_services:
            try:
                res = c.compound([op.putrootfh()])
                err = "operation erroneously suceeding"
            except rpc.RPCDeniedError as e:
                if e.stat == rpc.AUTH_ERROR and e.astat == rpc.AUTH_BADCRED:
                    # This is correct response
                    pass
                else:
                    err = str(e)
            except Exception as e:
                err = str(e)
            if err is not None:
                t.fail("Using bad gss service number %i "
                       "should return AUTH_BADCRED, instead got %s" %
                       (service, err))
    finally:
        c.security = orig
