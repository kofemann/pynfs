import use_local # HACK so don't have to rebuild constantly
import rpc.rpc as rpc
import nfs4lib
from nfs4lib import NFS4Error, NFS4Replay, inc_u32
from xdrdef.nfs4_type import *
from xdrdef.nfs4_const import *
from xdrdef.sctrl_pack import SCTRLPacker, SCTRLUnpacker
import nfs_ops
op = nfs_ops.NFS4ops()
import time, struct
import threading
import hmac
import inspect
from os.path import basename
from nfs4commoncode import CBCompoundState as CompoundState, \
     cb_encode_status as encode_status, \
     cb_encode_status_by_name as encode_status_by_name


import traceback
import logging
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)-7s:%(name)s:%(message)s")
log_cb = logging.getLogger("nfs.client.cb")

op4 = nfs_ops.NFS4ops()
SHOW_TRAFFIC = 0

class NFS4Client(rpc.Client, rpc.Server):
    def __init__(self, host=b'localhost', port=2049, minorversion=1, ctrl_proc=16, summary=None, secure=False):
        rpc.Client.__init__(self, 100003, 4)
        self.prog = 0x40000000
        self.versions = [1] # List of supported versions of prog

        self.minorversion = minorversion
        self.minor_versions = [minorversion]
        self.tag = b"default tag"
        self.impl_id = nfs_impl_id4(b"citi.umich.edu", b"pynfs X.X",
                                    nfs4lib.get_nfstime())
        self.verifier = struct.pack('>d', time.time())
        self.server_address = (host, port)
        self.c1 = self.connect(self.server_address,secure=secure)
        self.sessions = {} # XXX Really, this should be per server
        self.clients = {} # XXX Really, this should be per server
        self.ctrl_proc = ctrl_proc
        self.summary = summary

    def set_cred(self, credinfo):
        self.default_cred = credinfo

    def control_async(self, data=""):
        p = SCTRLPacker()
        p.pack_CTRLarg(data)
        return self.send_call(self.c1, self.ctrl_proc, p.get_buffer())

    def control(self, *args, **kwargs):
        xid = self.control_async(*args, **kwargs)
        pipe = self.c1
        header, data = pipe.listen(xid, 30.0)
        if data:
            p = SCTRLUnpacker(data)
            data = p.unpack_CTRLres()
        return data

    def null_async(self, data=b""):
        return self.send_call(self.c1, 0, data)

    def null(self, *args, **kwargs):
        xid = self.null_async(*args, **kwargs)
        return self.listen(xid)

    def compound_async(self, ops, credinfo=None, pipe=None,
                       tag=None, version=None, checks=True,
                       packer=nfs4lib.FancyNFS4Packer):
        if tag is None:
            tag = self.tag
        if version is None:
            version = self.minorversion
        if credinfo is None:
            credinfo = self.default_cred
        if pipe is None:
            pipe = self.c1
        p = packer(check_enum=checks, check_array=checks)
        c4 = COMPOUND4args(tag, version, ops)
        if SHOW_TRAFFIC:
            log_cb.info("compound args = %r" % (c4,))
        p.pack_COMPOUND4args(c4)
        return self.send_call(pipe, 1, p.get_buffer(), credinfo)

    def compound(self, *args, **kwargs):
        self.tag = self.create_tag()
        xid = self.compound_async(*args, **kwargs)
        pipe = kwargs.get("pipe", None)
        res = self.listen(xid, pipe=pipe)
        if SHOW_TRAFFIC:
            log_cb.info("compound result = %r" % (res,))
        if self.summary:
            self.summary.show_op('call v4.1 %s:%s' % self.server_address,
                [ nfs_opnum4[a.argop].lower()[3:] for a in args[0] ],
                nfsstat4[res.status])
        return res

    def listen(self, xid, pipe=None, timeout=300):
        if pipe is None:
            pipe = self.c1
        header, data = pipe.listen(xid, timeout)
        if data:
            p = nfs4lib.FancyNFS4Unpacker(data)
            data = p.unpack_COMPOUND4res()
        return data

    def handle_0(self, data, cred):
        """NULL procedure"""
        allow_null_data = True
        log_cb.info("*" * 20)
        log_cb.info("Handling CB_NULL")
        if data and not allow_null_data:
            return rpc.GARBAGE_ARGS, None
        else:
            return rpc.SUCCESS, ''

    def handle_1(self, data, cred):
        # STUB
        log_cb.info("*" * 20)
        log_cb.info("Handling CB_COMPOUND")
        p = nfs4lib.FancyNFS4Packer()
        res = CB_COMPOUND4res(NFS4ERR_BACK_CHAN_BUSY, "STUB CB_REPLY", [])
        p.pack_CB_COMPOUND4res(res)
        return rpc.SUCCESS, p.get_buffer()

    def handle_1(self, data, cred):
        log_cb.info("*" * 20)
        log_cb.info("Handling COMPOUND")
        # data is an XDR packed string.  Unpack it.
        unpacker = nfs4lib.FancyNFS4Unpacker(data)
        try:
            args = unpacker.unpack_CB_COMPOUND4args()
            unpacker.done()
        except:
            log_cb.warn("returning GARBAGE_ARGS")
            log_cb.debug("unpacking raised the following error", exc_info=True)
            return rpc.GARBAGE_ARGS, None
        log_cb.debug(repr(args))
        try:
            # SEQUENCE needs to know size of request
            args.req_size = len(data)
            # Handle the request
            env = self.op_cb_compound(args, cred)
            log_cb.info(repr(env.results.reply.results))
            # Pack the results back into an XDR string
            p = nfs4lib.FancyNFS4Packer()
            p.pack_CB_COMPOUND4res(CB_COMPOUND4res(env.results.reply.status,
                                                   env.results.reply.tag,
                                                   env.results.reply.results))
            data = p.get_buffer()
            # Stuff the replay cache
            if env.cache is not None:
                p.reset()
                p.pack_CB_COMPOUND4res(CB_COMPOUND4res(env.results.cache.status,
                                                       env.results.cache.tag,
                                                       env.results.cache.results))
                env.cache.data = p.get_buffer()
                env.cache.valid.set()
        except NFS4Replay as e:
            log_cb.info("Replay...waiting for valid data")
            e.cache.valid.wait()
            log_cb.info("Replay...sending data")
            data = e.cache.data
        return rpc.SUCCESS, data, getattr(env, "notify", None)

    def check_utf8str_cs(self, str):
        # XXX combine code with server
        # STUB - raises NFS4Error if appropriate.
        # Can be NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME
        pass

    def op_cb_compound(self, args, cred):
        env = CompoundState(args, cred)
        # Check for problems with the compound itself
        if args.minorversion != 0:
            if args.minorversion not in self.minor_versions:
                env.results.set_empty_return(NFS4ERR_MINOR_VERS_MISMATCH)
                return env
        try:
            self.check_utf8str_cs(args.tag)
        except NFS4Errror as e:
            env.results.set_empty_return(e.status, "Invalid utf8 tag")
            return env
        # Handle the individual operations
        status = NFS4_OK
        for arg in args.argarray:
            opname = nfs_cb_opnum4.get(arg.argop, 'op_cb_illegal')
            log_cb.info("*** %s (%d) ***" % (opname, arg.argop))
            env.index += 1
            # Look for function self.op_<name>
            funct = getattr(self, opname.lower(), None)
            if funct is None:
                # If it doesn't exist, return _NOTSUPP
                result = encode_status_by_name(opname.lower()[3:],
                                               NFS4ERR_NOTSUPP)
            else:
                try:
                    # Otherwise, call the function
                    result = funct(arg, env)
                except NFS4Error as e:
                    # XXX NOTE this only works for error returns that
                    # include no data.  Must ensure others (eg setattr)
                    # catch error themselves to encode properly.
                    result = encode_status_by_name(opname.lower()[3:],
                                                   e.status, msg=e.tag)
                except NFS4Replay:
                    # Just pass this on up
                    raise
                except StandardError:
                    # Uh-oh.  This is a server bug
                    traceback.print_exc()
                    result = encode_status_by_name(opname.lower()[3:],
                                                   NFS4ERR_SERVERFAULT)
            env.results.append(result)
            status = result.status
            if status != NFS4_OK:
                break
        log_cb.info("Replying.  Status %s (%d)" % (nfsstat4[status], status))
        return env

    def prehook(self, arg, env):
        """Call the function pre_<opname>_<clientid> if it exists"""
        if env.session is None:
            raise
            return
        cid = env.session.client.clientid
        opname = nfs_cb_opnum4.get(arg.argop, 'op_cb_illegal').lower()[3:]
        funct = getattr(self, "pre_%s_%i" % (opname, cid), None)
        if funct is None:
            return
        funct(arg, env)

    def posthook(self, arg, env, res=None):
        """Call the function post_<opname>_<clientid> if it exists"""
        if env.session is None:
            raise
            return res
        cid = env.session.client.clientid
        opname = nfs_cb_opnum4.get(arg.argop, 'op_cb_illegal').lower()[3:]
        funct = getattr(self, "post_%s_%i" % (opname, cid), None)
        if funct is None:
            return res
        return funct(arg, env, res)

    def op_cb_sequence(self, arg, env):
        log_cb.info("In CB_SEQUENCE")
        if env.index != 0:
            return encode_status(NFS4ERR_SEQUENCE_POS)
        session = self.sessions.get(arg.csa_sessionid, None)
        if session is None:
            return encode_status(NFS4ERR_BADSESSION)
        # STUB - check connectino binding and creds
        channel = session.back_channel
        # STUB bounds checking
        try:
            slot = channel.slots[arg.csa_slotid]
        except IndexError:
            return encode_status(NFS4ERR_BADSLOT)
        env.cache = slot.check_seqid(arg.csa_sequenceid)
        # AT this point we are not allowed to return an error
        env.caching = arg.csa_cachethis
        env.session = session
        res = CB_SEQUENCE4resok(session.sessionid, slot.seqid,
                                arg.csa_slotid,
                                channel.maxrequests, channel.maxrequests)# STUB
        res = self.posthook(arg, env, res)
        return encode_status(NFS4_OK, res)

    def op_cb_recall(self, arg, env):
        log_cb.info("In CB_RECALL")
        self.prehook(arg, env)
        res = self.posthook(arg, env, res=NFS4_OK)
        return encode_status(res)

    def op_cb_layoutrecall(self, arg, env):
        log_cb.info("In CB_LAYOUTRECALL")
        self.prehook(arg, env)
        res = self.posthook(arg, env, res=NFS4_OK)
        if res is not NFS4_OK:
            return encode_status(res)

        op_lorecall = arg.opcblayoutrecall
        lo_type = op_lorecall.clora_type
        lo_iomode = op_lorecall.clora_iomode
        lo_recall = op_lorecall.clora_recall
        lo_recalltype = lo_recall.lor_recalltype
        if lo_recalltype is LAYOUTRECALL4_FILE:
            rclayout = lo_recall.lor_layout
            ops = [op.putfh(rclayout.lor_fh),
                   op.layoutreturn(False, lo_type, lo_iomode,
                      layoutreturn4(LAYOUTRETURN4_FILE,
                                    layoutreturn_file4(rclayout.lor_offset,
                                                       rclayout.lor_length, \
                                                       rclayout.lor_stateid, b"")))]
            env.session.compound(ops)
        elif lo_recalltype not in [LAYOUTRECALL4_FSID, LAYOUTRECALL4_ALL]:
            res = NFS4ERR_NOTSUPP
        return encode_status(res)

    def new_client(self, name, verf=None, cred=None, protect=None, flags=0,
                   expect=NFS4_OK):
        """Establish a new client_id with the server"""
        if verf is None:
            verf = self.verifier
        owner = client_owner4(verf, name)
        if protect is None:
            protect = state_protect4_a(SP4_NONE)
        res = self.compound([op4.exchange_id(owner, flags, protect,
                                            [self.impl_id])],
                            cred)
        nfs4lib.check(res, expect)
        if expect == NFS4_OK:
            client_rec = ClientRecord(res.resarray[0], self, cred, protect)
            self.clients[client_rec.clientid] = client_rec
            return client_rec
        else:
            return None

    def new_client_session(self, name, flags=0, sec=None):
        c = self.new_client(name, flags=flags)
        s = c.create_session(sec=sec)
        s.compound([op4.reclaim_complete(FALSE)])
        return s

    def new_pnfs_client_session(self, name, flags=EXCHGID4_FLAG_USE_PNFS_MDS, sec=None):
        # Make sure E_ID returns MDS capabilities
        c = self.new_client(name, flags=flags)
        if not c.flags & EXCHGID4_FLAG_USE_PNFS_MDS:
            fail("Server can not be used as pnfs metadata server")
        s = c.create_session(sec=sec)
        s.compound([op4.reclaim_complete(FALSE)])
        return s

    def create_tag(self):
        current_module = inspect.getmodule(inspect.currentframe().f_back)
        current_stack = inspect.stack()
        stackid = 0
        while current_module == inspect.getmodule(current_stack[stackid][0]):
              stackid = stackid + 1
        test_name = '%s:%s' % (basename(current_stack[stackid][1]), current_stack[stackid][3])
        return os.fsencode(test_name)

class ClientStateProtection(object):
    def __init__(self, p_res, p_arg):
        self.type = p_res.spr_how
        if self.type == SP4_SSV:
            hash_oid = p_arg.ssp_hash_algs[p_res.spi_hash_alg]
            hash_alg = nfs4lib.hash_algs[hash_oid]
            encrypt_oid = p_arg.ssp_encr_algs[p_res.spi_encr_alg]
            encrypt_alg = nfs4lib.encrypt_algs[encrypt_oid]
            self.context = nfs4lib.SSVContext(hash_alg, encrypt_alg,
                                              p_res.spi_window)
            if self.context.ssv_len != p_res.spi_ssv_len:
                raise "Some error here" # STUB

class ClientRecord(object):
    def __init__(self, eir, dispatcher, cred, protect_args):
        """Takes as input result from EXCHANGE_ID"""
        self.c = dispatcher
        self.cred = cred
        self.clientid = eir.eir_clientid
        self.seqid = eir.eir_sequenceid
        self.flags = eir.eir_flags
        self._sec = rpc.security.AuthGss()
        self.ssv_creds = []
        self.protect = ClientStateProtection(eir.eir_state_protect,
                                             protect_args)
        if self.protect.type == SP4_SSV:
            self._add_ssv_handles(eir.eir_state_protect.spi_handles)

    def _add_ssv_handles(self, handles):
        creds = [self._sec.init_given_context(self.protect.context, handle,
                                              rpc.gss_const.rpc_gss_svc_privacy)
                 for handle in handles]
        self.ssv_creds.extend(creds)

    def _create_session(self,
                       flags=CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
                       fore_attrs=None, back_attrs=None, sec=None,
                       prog=None,
                       max_retries=1, delay_time=1):
        chan_attrs = channel_attrs4(0,8192,8192,8192,128,8,[])
        if fore_attrs is None:
            fore_attrs = chan_attrs
        if back_attrs is None:
            back_attrs = chan_attrs
        if sec is None:
            sec= [callback_sec_parms4(0)]
        if prog is None:
            prog = self.c.prog
        for item in range(max_retries):
            res = self.c.compound([op4.create_session(self.clientid, self.seqid,
                                                 flags,
                                                 fore_attrs, back_attrs,
                                                 prog, sec)],
                              self.cred)
            if res.status != NFS4ERR_DELAY:
                break
            time.sleep(delay_time)
        return res;

    def create_session(self,
                       flags=CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
                       fore_attrs=None, back_attrs=None, sec=None, prog=None):
        res = self._create_session(flags=flags,
                        fore_attrs=fore_attrs, back_attrs=back_attrs,
                        sec=sec, prog=prog, max_retries=10);
        nfs4lib.check(res)
        return self._add_session(res.resarray[0])

    def _add_session(self, csr):
        self.seqid = inc_u32(csr.csr_sequence) # XXX Do we need to check this?
        sess = SessionRecord(csr, self)
        self.c.sessions[sess.sessionid] = sess
        return sess

    def _cb_hook(self, prefix, opname, funct):
        hook_name = "%s_%s_%i" % (prefix, opname, self.clientid)
        if funct is None:
            # Remove hook
            try:
                delattr(self.c, hook_name)
            except AttributeError:
                pass
        else:
            # Add hook
            setattr(self.c, hook_name, funct)

    def cb_pre_hook(self, op_num, funct=None):
        if op_num == OP_CB_SEQUENCE:
            raise RuntimeError("Hook depends on session info from CB_SEQUENCE")
        self._cb_hook("pre", nfs_cb_opnum4[op_num][3:].lower(), funct)

    def cb_post_hook(self, op_num, funct=None):
        self._cb_hook("post", nfs_cb_opnum4[op_num][3:].lower(), funct)

# XXX FIXME - this is for Slot code, put in reuasable spot if this works
from nfs4server import Slot
from nfs4server import Channel as RecvChannel

class SendChannel(object):
    def __init__(s, attrs):
        s.lock = threading.Lock()
        s.connections = [] # communication info
        s.maxrequestsize = attrs.ca_maxrequestsize
        s.maxresponsesize = attrs.ca_maxresponsesize
        s.maxresponsesize_cached = attrs.ca_maxresponsesize_cached
        s.maxoperations = attrs.ca_maxoperations
        s.maxrequests = attrs.ca_maxrequests
        s.slots = [Slot(i) for i in range(s.maxrequests)]

    def choose_slot(self):
        self.lock.acquire()
        try:
            for slot in self.slots:
                if not slot.inuse:
                    slot.inuse = True
                    return slot
            raise RuntimeError("Out of slots")
        finally:
            self.lock.release()

class SessionRecord(object):
    def __init__(self, csr, client):
        self.sessionid = csr.csr_sessionid
        self.seqid = csr.csr_sequence
        self.client = client
        self.c = client.c
        self.cred = client.cred
        self.fore_channel = SendChannel(csr.csr_fore_chan_attrs)
        self.back_channel = RecvChannel(csr.csr_back_chan_attrs)
        # STUB - and other stuff

    def seq_op(self, slot=None, seq_delta=1, cache_this=False):
        if slot is None:
            slot = self.fore_channel.choose_slot()
        else:
            # XXX Does anyone use this? it will likely break things
            raise RuntimeError
            slot = self.fore_channel.slots[slot]
        # STUB, need to properly set highest
        return op4.sequence(self.sessionid, slot.get_seqid(seq_delta),
                           slot.id, slot.id, cache_this)

    def set_ssv(self, ssv=None, *args, **kwargs):
        protect = self.client.protect
        if ssv is None:
            ssv = nfs4lib.random_string(protect.context.ssv_len)
        if "credinfo" not in kwargs:
            kwargs["credinfo"] = self.cred
        seq_op = self.seq_op(kwargs.pop("slot", None))
        p = nfs4lib.FancyNFS4Packer()
        p.pack_SEQUENCE4args(seq_op.opsequence)
        digest =  protect.context.hmac(p.get_buffer(), SSV4_SUBKEY_MIC_I2T)
        ssv_op = op4.set_ssv(ssv, digest)
        res = self.c.compound([seq_op, ssv_op], *args, **kwargs)
        # STUB - do some checking
        protect.context.set_ssv(ssv)
        return res

    def _prepare_compound(self, kwargs):
        """Common prep for both async and sync compound call.

        Returns seq_op to prepend, and manipulates the kwargs dict.
        """
        if "credinfo" not in kwargs:
            kwargs["credinfo"] = self.cred
        seq_op = self.seq_op(kwargs.pop("slot", None),
                             kwargs.pop("seq_delta", 1),
                             kwargs.pop("cache_this", False))
        slot = self.fore_channel.slots[seq_op.sa_slotid]
        return slot, seq_op

    def compound_async(self, ops, **kwargs):
        slot, seq_op = self._prepare_compound(kwargs)
        slot.xid = self.c.compound_async([seq_op] + ops, **kwargs)
        return slot

    def listen(self, slot, pipe=None):
        res = self.c.listen(slot.xid, pipe=pipe)
        slot.xid = None
        res = self.update_seq_state(res, slot)
        res = self.remove_seq_op(res)
        return res

    def compound(self, ops, **kwargs):
        max_retries = 10
        delay_time = 1
        handle_state_errors = kwargs.pop("handle_state_errors", True)
        saved_kwargs = kwargs
        slot, seq_op = self._prepare_compound(kwargs)
        for item in range(max_retries):
            res = self.c.compound([seq_op] + ops, **kwargs)
            res = self.update_seq_state(res, slot)
            if res.status != NFS4ERR_DELAY or not handle_state_errors:
                break
            if res.resarray[0].sr_status != NFS4ERR_DELAY:
                # As per errata ID 2006 for RFC 5661 section 15.1.1.3
                # don't update the slot and sequence ID if the sequence
                # operation itself receives NFS4ERR_DELAY
                slot, seq_op = self._prepare_compound(saved_kwargs)
            time.sleep(delay_time)
        res = self.remove_seq_op(res)
        return res

    def update_seq_state(self, res, slot):
        seq_res = res.resarray[0]
        slot.finish_call(seq_res)
        return res

    def remove_seq_op(self, res):
        if res.resarray[0].sr_status == NFS4_OK:
            # STUB - do some checks
            res.resarray = res.resarray[1:]
        return res

##     def open(self, owner, name=None, type=OPEN4_NOCREATE,
##              mode=UNCHECKED4, attrs={FATTR4_MODE:0o644}, verf=None,
##              access=OPEN4_SHARE_ACCESS_READ,
##              deny=OPEN4_SHARE_DENY_WRITE,
##              claim_type=CLAIM_NULL, deleg_type=None, deleg_cur_info=None):
##         if name is None:
##             name = owner
##         seqid = self.get_seqid(owner)
##         openowner = open_owner4(self.clientid, owner)
##         if type == OPEN4_NOCREATE:
##             openhow = openflag4(type)
##         elif type == OPEN4_CREATE:
##             openhow = openflag4(type, createhow4(mode, attrs, verf))
##         claim = open_claim4(claim_type, name, deleg_type, deleg_cur_info)
##         return self.open_op(seqid, access, deny, openowner, openhow, claim)

"""Gss init local
import nfs4client
C = nfs4client.NFS4Client("tiffin")
import rpc.security as security
sec = security.AuthGss()
call = C.make_call_function(C.c1, 0, sec, 100003, 4)
sec.init_cred(call, "nfs@tiffin")
"""

"""Gss init tiffin
import nfs4client
C = nfs4client.NFS4Client()
import rpc.security as security
sec = security.AuthGss()
call = C.make_call_function(C.c1, 0, 100003, 4)
sec.init_cred(call)
"""

""" EXCHANGE_ID
import nfs4client
from xdrdef.nfs4_type import *
from xdrdef.nfs4_const import *
import nfs_ops
op = nfs_ops.NFS4ops()
owner = client_owner4("12345678","MyClientName")
protect = state_protect4_a(SP4_NONE)
C = nfs4client.NFS4Client()
C.compound([op.exchange_id(owner, 0, protect, [C.impl_id])])
"""

""" CREATE_SESSION
sha1 = '+\x0e\x03\x02\x1a'
sha256 = '`\x86H\x01e\x03\x04\x02\x01'
binding_opts = conn_binding4args(True, ["gibberish", sha256])
fore_attrs = channel_attrs4(4096,4096,4096,128,8,[])
cb_sec= callback_sec_parms4(0)
C.compound([C.create_session_op(0,1,0,0,binding_opts, fore_attrs, fore_attrs,123,[cb_sec])])
"""

""" SEQUENCE
C.compound([C.sequence_op("0000000000000001",1,0,8,True)])

"""

""" SET_SSV
import hmac, hashlib
import nfs4lib
p = nfs4lib.FancyNFS4Packer()
p.reset()
seq = C.sequence_op("0000000000000001",1,0,8,True)
p.pack_SEQUENCE4args(seq.opsequence)
digest = hmac.new("\0"*32, p.get_buffer(), hashlib.sha256).digest()
C.compound([seq, C.set_ssv_op('\1'*32, digest)])
"""

""" BIND_CONN_TO_SESSION
p.reset()
p.pack_bctsa_digest_input4(bctsa_digest_input4('0000000000000001', 42, 0))
digest = hmac.new("\1"*32, p.get_buffer(), hashlib.sha256).digest()
C.compound([C.bind_conn_to_session_op('0000000000000001', True, 3, False, 42, digest)])
C.listen()
res = _
p.reset()
p.pack_bctsa_digest_input4(bctsa_digest_input4('0000000000000001', 73, res.resarray[0].bctsr_nonce))
digest = hmac.new("\1"*32, p.get_buffer(), hashlib.sha256).digest()
C.compound([C.bind_conn_to_session_op('0000000000000001', False, 3, False, 73, digest)])
"""


""" PROGRAM COVERAGE
python2.7 ~/py_install/bin/coverage.py -x nfs4server.py
coverage.py -a -d cover nfs4server.py
run test suite
"""
