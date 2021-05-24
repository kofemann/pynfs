#!/usr/bin/env python3
from __future__ import with_statement
import use_local # HACK so don't have to rebuild constantly
import nfs4lib
from nfs4lib import inc_u32, NFS4Error, NFS4Replay
import rpc.rpc as rpc
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.sctrl_pack import SCTRLPacker, SCTRLUnpacker
import xdrdef.sctrl_type, xdrdef.sctrl_const
import traceback, threading
from locking import Lock, Counter
import time
import hmac
import random
import struct
import collections
import logging
from nfs4state import find_state
from nfs4commoncode import CompoundState, encode_status, encode_status_by_name
from fs import RootFS, ConfigFS
from config import ServerConfig, ServerPerClientConfig, OpsConfigServer, Actions

logging.basicConfig(level=logging.WARN,
                    format="%(levelname)-7s:%(name)s:%(message)s")
log_41 = logging.getLogger("nfs.server")

log_cfg = logging.getLogger("nfs.server.opconfig")

##################################################
# Set various global constants and magic numbers #
##################################################

NFS4_PORT = 2049 # default port server listens on, per draft22 2.9.3
CONTROL_PROCEDURE = 16 # default procedure number used to send sctrl.x commands

# Create some needed reply strings
def create_default_replays():
    # This only needs to be called once
    tag = b"auto-created replay response"
    p = nfs4lib.FancyNFS4Packer()
    res = encode_status_by_name("create_session", NFS4ERR_SEQ_MISORDERED)
    p.pack_COMPOUND4res(COMPOUND4res(NFS4ERR_SEQ_MISORDERED, tag, [res]))
    s1 = p.get_buffer()

    res = encode_status_by_name("sequence", NFS4ERR_SEQ_MISORDERED)
    p.reset()
    p.pack_COMPOUND4res(COMPOUND4res(NFS4ERR_SEQ_MISORDERED, tag, [res]))
    s2 = p.get_buffer()

    return s1, s2

default_replay_client, default_replay_slot = create_default_replays()

##################################################
# global functions
##################################################


def check_secured_gss(env):
    """Verify using GSS with integ or privacy"""
    # STUB
    # QUESTION what error should we raise?
    return

def check_size(env, *args):
    """Expected to raise NFS4Error() exception if there are problems"""
    # STUB - does no size checking
    return

def check_size_fixed(env, size):
    """Same as check_size, but are given size of XDR-ed nfs4_resop4"""
    # STUB - does no size checking

def check_session(env, unique=False):
    """Ops must be within a session, unless unique is True.

    If unique is True, then it is allowed to be outside a session, but then
    it must be the only op in the compound.
    """
    if unique and env.index == 0:
        if len(env.argarray) != 1:
            raise NFS4Error(NFS4ERR_NOT_ONLY_OP)
    elif env.session is None:
        raise NFS4Error(NFS4ERR_OP_NOT_IN_SESSION)
    check_size(env)

def check_cfh(env):
    if env.cfh is None:
        raise NFS4Error(NFS4ERR_NOFILEHANDLE)

def check_sfh(env):
    if env.sfh is None:
        raise NFS4Error(NFS4ERR_NOFILEHANDLE)

def check_seqid(seqid):
    """Defunct function, kept to remind me of the changed requirements."""
    if True:
        return
    # This restriction has been lifted as of draft15
    if seqid != 0:
        raise NFS4Error(NFS4ERR_INVAL, tag="seqid must be zero in 4.1")

##################################################
# Supporting class definitions
##################################################

class Recording(object):
    """Store RPC traffic for client"""
    def __init__(self):
        self.reset()

    def add(self, call, reply):
        """Add call and reply strings to records"""
        if self.on:
            self.queue.appendleft((call, reply))

    def set_stamp(self, stamp):
        queue = self.queues.get(stamp, None)
        if queue is None:
            queue = collections.deque()
            self.queues[stamp] = queue
        self.queue = queue

    def reset(self):
        self.stamp = "default"
        self.on = False
        self.queues = {}
        self.queue = None

class StateProtection(object):
    def __init__(self, arg, client):
        self.client = client
        self.type = arg.spa_how
        if self.type != SP4_NONE:
            self.must_enforce = arg.spo_must_enforce
            self.must_allow = arg.spo_must_allow
        if self.type == SP4_SSV:
            self.ssv_seq = 0
            # Choose hash algorithm
            for i, oid in enumerate(arg.ssp_hash_algs):
                hash_funct = nfs4lib.hash_algs.get(oid, None)
                if hash_funct is not None:
                    break
            else:
                raise NFS4Error(NFS4ERR_HASH_ALG_UNSUPP)
            self.hash_index = i
            # Choose encryption algorithm
            for i, oid in enumerate(arg.ssp_encr_algs):
                enc_factory = nfs4lib.encrypt_algs.get(oid, None)
                if enc_factory is not None:
                    break
            else:
                raise NFS4Error(NFS4ERR_ENCR_ALG_UNSUPP)
            self.encrypt_index = i
            self.context = nfs4lib.SSVContext(hash_funct, enc_factory,
                                              min(16, arg.ssp_window),
                                              client=False)

            self.lock = Lock("ssv")

    def deny(self, env, op, bypass_ssv=False):
        """Raise error if op in must_enforce and MECH/SSV checks fail"""
        # STUB
        err_code = NFS4ERR_ACCESS # XXX what error to use?
        if self.type == SP4_NONE or not ((1<<op) & self.must_enforce):
            return
        check_secured_gss(env)
        if self.type == SP4_MACH_CRED:
            if env.principal != self.client.principal or \
               env.mech != self.client.mech:
                raise NFS4Error(err_code, tag="Failed machine_cred check")
        elif self.type == SP4_SSV:
            if env.mech != nfs4lib.ssv_mech_oid:
                if bypass_ssv:
                    if env.principal == self.client.principal and \
                       env.mech == self.client.mech:
                        return
                raise NFS4Error(err_code, tag="Did not use ssv gss_mech")

    def rv(self, arg):
        """Fills in data structure for part of EID return"""
        # STUB This is al sorts of buggy in more complicated situations,
        # But will work for the first EID
        rv = state_protect4_r(self.type)
        if self.type == SP4_MACH_CRED:
            rv.spr_mach_ops = state_protect_ops4(self.must_enforce,
                                                 self.must_allow)
        elif self.type == SP4_SSV:
            handles = [self.client.get_new_handle()
                       for i in range(arg.ssp_num_gss_handles)]
            info = ssv_prot_info4(state_protect_ops4(self.must_enforce,
                                                     self.must_allow),
                                  self.hash_index,
                                  self.encrypt_index,
                                  self.context.ssv_len,
                                  self.context.window,
                                  handles)
            rv.spr_ssv_info = info
        return rv



class ClientList(object):
    """Manage mapping of clientids to server data.

    Handles the handing out of clientids, the mapping of
    client supplied ownerid to server supplied clientid, and
    the mapping of either to ClientRecords, where all of the
    server's state data related to the client can be accessed.
    """
    def __init__(self):
        self._data = {}
        self.lock = Lock("ClientList")
        self._nextid = 0

    def __getitem__(self, key):
        return self._data.get(key)

    def __delitem__(self, clientid):
        with self.lock:
            self.remove(clientid)

    def remove(self, clientid):
        """Remove a client and its state.

        Lock needs to be held.
        """
        # STUB - do we need to set some sort of invalid flag on the
        # ClientRecord, since it may be in use by another thread.
        c = self._data[clientid]
        del self._data[clientid]
        del self._data[c.ownerid]
        c.freeze = True

    def add(self, arg, principal, security):
        """Add a new client using EXCHANGE_ID4args.

        Lock needs to be held.
        """
        c = ClientRecord(self._nextid, arg, principal, security=security)
        if c.ownerid in self._data:
            raise RuntimeError("ownerid %r already in ClientList" %
                               c.ownerid)
        # STUB - want to limit size of _nextid to < 2**32, to
        # accomodate ConfigFS, which embeds clientid into fileid.
        # BUG - clientid is supposed to be unique, even across
        # server reboots (2.4 of draft22, line 1408)
        self._nextid += 1
        # Since ownerid is a string, and clientid an integer, we
        # can record both without fear of collision.
        self._data[c.ownerid] = c
        self._data[c.clientid] = c
        return c

    def wipe(self):
        with self.lock:
            self._data = {}

class VerboseDict(dict):
    def __init__(self, config):
        dict.__init__(self)
        self.config = config

    def __setitem__(self, key, value):
        if self.config.debug_state:
            log_41.info("+++ Adding client.state[%r]" % key)
        dict.__setitem__(self, key, value)

    def __delitem__(self, key):
        if self.config.debug_state:
            log_41.info("+++ Removing client.state[%r]" % key)
        dict.__delitem__(self, key)

class ClientRecord(object):
    """The server's representation of a client and its state"""
    def __init__(self, id, arg, principal, mech=None, security=None):
        self.config = ServerPerClientConfig()
        self.clientid = id
        self.mech = mech
        self.security = security
        self.confirmed = False
        self.freeze = False # Set True if removed from ClientList
        self.update(arg, principal)
        self.session_replay = Slot(0, default=default_replay_client) # v4.1 cache for just CREATE_SESSION
        self.sessions = [] # sessions associated with this clientid
        self.lastused = time.time() # time of last "RENEW" equivalant
        self.state = VerboseDict(self.config) # {other_id : StateTableEntry}
        self._next = 1 # counter for generating unique stateid 'other'
        self._handle_ctr = Counter(name="ssv_handle_counter")
        self._lock = Lock("Client")

    def update(self, arg, principal):
        """Update properties of client based on EXCHANGE_ID arg"""
        if self.confirmed:
            # STUB - a confirmed update is much more restricted
            #      - for example, self.protection should not be modified
            return
        self.principal = principal
        self.ownerid = arg.eia_clientowner.co_ownerid
        self.verifier = arg.eia_clientowner.co_verifier
        if arg.eia_client_impl_id:
            self.impl_id = arg.eia_client_impl_id[0]
        else:
            self.impl_id = None
        self.use_profile = arg.eia_flags & EXCHGID4_FLAG_MASK_PNFS
        self.protection = StateProtection(arg.eia_state_protect, self)

    def principal_matches(self, xxx):
        if self.protection.type == SP4_NONE:
            # QUESTION: just return True here?
            return self.principal == env.principal
            return True
        else:
            # blah blah blah
            pass

    def get_new_handle(self):
        """Used to supply ssv gss handles in response to EID requests."""
        str = "handle_%i:%i" % (self.clientid, self._handle_ctr.next())
        self.security[rpc.RPCSEC_GSS]._add_context(self.protection.context, str)
        return str

    def get_new_other(self):
        self._lock.acquire()
        # NOTE we are only using 8 bytes of 12
        other = struct.pack("!Q", self._next)
        self._next += 1
        self._lock.release()
        return other

    def __hash__(self):
        """Guarantee this can be used as dict key"""
        return hash(self.clientid)

    def renew_lease(self):
        self.lastused = time.time()

    def rebooted(self):
        log_41.error("Client rebooted")
        # STUB - locking problems if server still handling other requests
        # Erase session state
        self.session_replay = Slot(0, default=default_replay_client)
        self.sessions = [] # sessions associated with this clientid
        # Erase share and record lock state
        for key, state in self.state.items():
            try:
                with state.lock:
                    if state.type in (SHARE, BYTE):
                        state.delete()
                    # STUB - what about LAYOUT?
                    # STUB - config whether DELEG OK or not
            except StandardError as e:
                log_41.exception("Ignoring problem during state removal")
        self.state = {}
        self.lastused = time.time()

    def find_active_cb_session(self):
        """Find and return a session that has a usable callback channel"""
        for sess in self.sessions:
            if sess.has_backchannel():
                return sess

class SessionRecord(object):
    """The server's representation of a session and its state"""
    def __init__(self, client, csa):
        self.client = client # reference back to client which created this session
        self.sessionid = "%08x%08x" % (client.clientid,
                                    client.session_replay.seqid) # XXX does this work?
        self.channel_fore = Channel(csa.csa_fore_chan_attrs, client.config) # Normal communication
        self.channel_back = Channel(csa.csa_back_chan_attrs, client.config) # Callback communication
        self.persist = False # see 2.10.4.5 STUB - currently no way to set True
        self.headerpadsize = 0 # STUB - ignored
        self.binding = (client.protection.type != SP4_NONE)
        self.nonce = {} # Store nonce while waiting for challange response
        #self.ssv = None # crypto hash for securing channel binding
        #            short for "Secret Session Verifier"
        self.cb_prog = None # callback rpc program number
        # NOTE 2.10.6.3 implies multiple principals can use a session
        # but 2.4 implies principal linked with ownerid (ie client)

    def get_nonce(self, connection, client_nonce):
        """Get (and remember) nonce for the connection"""
        # NOTE XXX nonce records should have timestamps to allow removal
        # of stale data.  Also, is keying on connection enough?
        nonce = random.randint(0, 0xffffffffffffffff)
        while nonce == client_nonce:
            nonce = random.randint(0, 0xffffffffffffffff)
        self.nonce[connection] = (nonce, client_nonce)
        return nonce

    def has_backchannel(self):
        if len(self.channel_back.connections) > 0:
            return True
        return False

class Channel(object):
    #STUB: need to fix slot management for the backchannel
    def __init__(self, attrs, config=None):
        self.connections = [] # communication info
        self.maxrequestsize = attrs.ca_maxrequestsize
        # This is over-the-wire.  Which means we must use a packed
        # COMPOUND4res limit of:
        # gss_wrap_size_limit(maxresponsesize - rpc_header - 4) - 8 - MIC_size
        self.maxresponsesize = attrs.ca_maxresponsesize
        self.maxresponsesize_cached = attrs.ca_maxresponsesize_cached
        self.maxoperations = attrs.ca_maxoperations
        self.maxrequests = attrs.ca_maxrequests
        self.adjust_attrs(config)
        self.slots = [Slot(i) for i in range(self.maxrequests)]
        self.lock = Lock("Channel")

    def choose_slot(self):
        """ Used by the backchannel client"""
        with self.lock:
            for slot in self.slots:
                if not slot.inuse:
                    slot.inuse = True
                    return slot
        raise RuntimeError("Out of slots")

    def free_slot(self, slotid):
        """ Used by the backchannel client"""
        with self.lock:
            self.slots[slotid].inuse = False

    def adjust_attrs(self, config):
        """Take (client suggested) attrs, and adjust downwards"""
        if config is None:
            return
        self.maxrequestsize = min(self.maxrequestsize, config.maxrequestsize)
        self.maxresponsesize = min(self.maxresponsesize, config.maxresponsesize)
        self.maxresponsesize_cached = min(self.maxresponsesize_cached,
                                       self.maxresponsesize,
                                       config.maxresponsesize,
                                       config.maxresponsesize_cached)
        self.maxoperations = min(self.maxoperations, config.maxoperations)
        self.maxrequests = min(self.maxrequests, config.maxrequests)

    def get_attrs(self):
        return channel_attrs4(0, self.maxrequestsize,
                              self.maxresponsesize, self.maxresponsesize_cached,
                              self.maxoperations, self.maxrequests, [])

    def bind(self, connection):
        """Bind the connection to the channel"""
        if connection not in self.connections:
            self.connections.append(connection)


class Cache(object):
    def __init__(self, data=None):
        self.data = data
        self.valid = threading.Event() # XXX Is anyone waiting on this?
        if data is not None:
            self.valid.set()

class Slot(object):
    def __init__(self, index, default=default_replay_slot):
        self.id = index
        self.seqid = 0
        self.replay_cache = Cache(default)
        self.seen = False # server has determined that client has seen reply
        self.lock = Lock("Slot")
        self.inuse = False # client has outstanding message
        self.xid = None # rpc xid of outstanding message, only set on async calls

    def check_seqid(self, seqid):
        """Server replay checking"""
        self.lock.acquire()
        try:
            expected = inc_u32(self.seqid)
            if seqid == expected:
                # All is good
                self.seqid = expected
                self.replay_cache = Cache()
                self.seen = False
                return self.replay_cache
            elif seqid == self.seqid:
                # Replay
                """ NOTE XXX
                Must be a bit careful with replays, since it is possible
                for a retransmitted request to come in before we have coded
                a reply for the first request.
                """
                raise NFS4Replay(self.replay_cache)
            else:
                raise NFS4Error(NFS4ERR_SEQ_MISORDERED)
        finally:
            self.lock.release()

    def get_seqid(self, delta=1):
        """Client seqid"""
        # locking not needed, since slot is handed out under channel lock
        new_seqid = int( (self.seqid + delta) & 0xffffffff )
        return new_seqid

    def finish_call(self, seq_res):
        if seq_res.sr_status == NFS4_OK:
            self.seqid = seq_res.sr_sequenceid
        self.inuse = False

    # STUB - for client, need to track slot usage

class SummaryOutput:
    def __init__(self, enabled=True):
        self._enabled = enabled
        self._last = None
        self._last_role = None
        self._repeat_count = 0

    def show_op(self, role, opnames, status):
        if not self._enabled:
            return

        summary_line = "  %s" % ', '.join(opnames)

        if status != NFS4_OK and status != NFS3_OK:
            summary_line += " -> %s" % nfsstat4[status]

        print_summary_line = True
        if summary_line != self._last or role != self._last_role:
            if self._last and self._repeat_count:
                print("  (repeated %u times)" % self._repeat_count)
            self._last = summary_line
            self._repeat_count = 0
        else:
            print_summary_line = False
            self._repeat_count += 1

        if self._last_role != role:
            print
            print(role)
            self._last_role = role

        if print_summary_line:
            print(summary_line)


##################################################
# The primary class - it is excessively long     #
##################################################

class NFS4Server(rpc.Server):
    """Implement a nfsv4.1 server."""

    # As the only per-server attribute, lease_time is handled specially
    fattr4_lease_time = property(lambda s: s.config.lease_time)

    def __init__(self, **kwargs):
        # Handle ctrl_proc keyword
        ctrl_proc = kwargs.pop("ctrl_proc", CONTROL_PROCEDURE)
        setattr(self, "handle_%i" % ctrl_proc, self._handle_ctrl)
        # Call rpc.Server with appropriate defaults
        port = kwargs.pop("port", NFS4_PORT)
        self.is_mds = kwargs.pop("is_mds", False)
        self.is_ds = kwargs.pop("is_ds", False)

        self.verbose = kwargs.pop('verbose', False)
        if self.verbose:
            log_41.setLevel(logging.DEBUG) # XXX redundant?
            log_41.setLevel(9)
            log_cfg.setLevel(20)

        self.summary = SummaryOutput(kwargs.pop('show_summary', False))

        rpc.Server.__init__(self, prog=NFS4_PROGRAM, versions=[4], port=port,
                            **kwargs)
        self.root = RootFS().root # Root of exported filesystem tree
        self._fsids = {self.root.fs.fsid: self.root.fs} # {fsid: fs}
        self.clients = ClientList() # List of attached clients
        self.sessions = {} # List of attached sessions
        self.minor_versions = [1]
        self.config = ServerConfig()
        self.opsconfig = OpsConfigServer()
        self.actions = Actions()
        self.mount(ConfigFS(self), path="/config")
        self.verifier = struct.pack('>d', time.time())
        self.recording = Recording()
        self.devid_counter = Counter(name="devid_counter")
        self.devids = {} # {devid: device}
        # default cred for the backchannel -- currently supports only AUTH_SYS
        rpcsec = rpc.security.instance(rpc.AUTH_SYS)
        self.default_cred = rpcsec.init_cred(uid=4321,gid=42,name="mystery")
        self.err_inc_dict = self.init_err_inc_dict()

    def start(self):
        """Cause the server to start listening on the previously bound port"""
        try:
            rpc.Server.start(self)
        except KeyboardInterrupt:
            # Put user into console where can look at state of server
            if not self.config.catch_ctrlc or not self.verbose:
                raise
            import code
            import readline
            d = globals()
            d["self"] = self
            # readline.set_completer(complete)
            readline.parse_and_bind("tab: complete")
            code.InteractiveConsole(d).interact("Interact now")

    def reboot(self):
        # STUB - all sorts of locking issues to think through
        log_41.warn("CALLING REBOOT")
        self.verifier = struct.pack('>d', time.time())
        # STUB - need to implement grace period, and send info in SEQ flags
        self.sessions = {}
        self.clients.wipe()

    def mount(self, fs, path):
        """Mount the fs at the given path, creating the path if in RootFS.

        Note that order matters, since the mount hides anything beneath it.
        """
        print("Mounting %r on %r" % (fs.fsid, path))
        # Find directory object on which to mount fs
        dir = self.root
        principal = nfs4lib.NFS4Principal("root", system=True)
        for comp in nfs4lib.path_components(path):
            # BUG need lock on dir
            if not dir.exists(comp):
                if dir.fs.fsid != (0, 0): # Only allow creates if in RootFS
                    raise RuntimeError
                dir = dir.create(comp, principal, NF4DIR, {})[0]
            else:
                dir = dir.lookup(comp, None, principal)
        # Do the actual mount
        fs.mount(dir)
        self._fsids[fs.fsid] = fs
        fs.attach_to_server(self)

    def assign_deviceid(self, dev):
        """Filesystem callback so server can assign globally unique devid."""
        id = self.devid_counter.next()
        # Note not using first part of devid
        dev.devid = struct.pack("!QQ", 0, id)
        self.devids[dev.devid] = dev

    def find_device(self, devid, kind):
        return self.devids.get(devid)

    def _handle_ctrl(self, data, cred):
        """CTRL procedure

        Note this is used by client tester to control server behavior.
        It will be aliased by __init__ to some handle_%i.
        """
        log_cfg.info("*" * 40)
        log_cfg.info("CONTROL CODE RECEIVED")
        # data is an XDR packed string.  Unpack it.
        unpacker = SCTRLUnpacker(data)
        try:
            args = unpacker.unpack_CTRLarg()
            unpacker.done()
        except:
            log_cfg.debug("unpacking raised an error:", exc_info=True)
            return rpc.GARBAGE_ARGS, None
        log_cfg.info(repr(args))
        # Handle the given control operation
        opname = xdrdef.sctrl_const.ctrl_opnum.get(args.ctrlop, 'ctrl_illegal')
        funct = getattr(self, opname.lower(), None)
        if funct is None:
            # This shouldn't happen
            log_cfg.error("opname=%s" % opname)
            raise
        try:
            status, result = funct(args)
        except:
            # STUB - do something here
            raise
        # Now pack and return the result
        p = SCTRLPacker()
        # res = xdrdef.sctrl_type.CTRLres(status, xdrdef.sctrl_type.resdata_t(args.ctrlop))
        res = xdrdef.sctrl_type.CTRLres(status, result)
        p.pack_CTRLres(res)
        return rpc.SUCCESS, p.get_buffer()

    def handle_0(self, data, cred):
        """NULL procedure"""
        log_41.info("*" * 20)
        log_41.info("Handling NULL")
        if data and not self.config.allow_null_data:
            return rpc.GARBAGE_ARGS, None
        else:
            return rpc.SUCCESS, ''

    def handle_1(self, data, cred):
        """COMPOUND procedure"""
        log_41.info("*" * 40)
        log_41.info("Handling COMPOUND")
        # data is an XDR packed string.  Unpack it.
        unpacker = nfs4lib.FancyNFS4Unpacker(data)
        try:
            args = unpacker.unpack_COMPOUND4args()
            unpacker.done()
        except:
            log_41.info(repr(data))
            log_41.warn("returning GARBAGE_ARGS")
            log_41.debug("unpacking raised the following error", exc_info=True)
            return rpc.GARBAGE_ARGS, None
        log_41.info(repr(args))
        try:
            # SEQUENCE needs to know size of request
            args.req_size = len(data) # BUG, need to use cred.payload_size
            # Handle the request
            env = self.op_compound(args, cred)
            # Pack the results back into an XDR string
            res = COMPOUND4res(env.results.reply.status,
                               env.results.reply.tag,
                               env.results.reply.results)
            log_41.info(repr(res))
            p = nfs4lib.FancyNFS4Packer()
            p.pack_COMPOUND4res(res)
            reply = p.get_buffer()
            # Stuff the replay cache
            if env.cache is not None:
                p.reset()
                p.pack_COMPOUND4res(COMPOUND4res(env.results.cache.status,
                                                 env.results.cache.tag,
                                                 env.results.cache.results))
                env.cache.data = p.get_buffer()
                env.cache.valid.set()
        except NFS4Replay as e:
            log_41.info("Replay...waiting for valid data")
            e.cache.valid.wait()
            log_41.info("Replay...sending data")
            reply = e.cache.data
            unpacker.reset(reply)
            show = unpacker.unpack_COMPOUND4res()
            unpacker.done()
            log_41.info(repr(show))
        self.recording.add(data, reply)
        return rpc.SUCCESS, reply

    def init_err_inc_dict(self):
        seq = []
        for name in nfs_opnum4.values():
            seq.append(name.lower()[3:])
        dic = dict.fromkeys(seq, 0)
        return dic

    def increment_error_count(self, opname, ceiling):
        value = self.err_inc_dict[opname]
        value = value + 1
        if value >= ceiling:
            value = 0
        self.err_inc_dict[opname] = value;
        return value

    def check_opsconfig(self, env, opname):
        log_cfg.debug("FRED - in opsconfig")
        config = self.opsconfig
        # API is a list whose first element is a string determining messagetype
        # Subsequent list values are determined by messagetype
        l = getattr(config, opname)
        if l[0] == "ERROR":
            # Format is ["ERROR", code, freq]
            # Interrupts normal processing to return 'code' every 'freq' calls
            # Special case for freq==0 is to return 'code a single time
            error, ceiling = l[1:]
            if error == NFS4_OK:
                # Proceed with normal processing
                return
            if ceiling == 0:
                # Special case, trigger the error once then return to normal
                log_41.debug("ERROR: check_opsconfig RESET to NORMAL")
                setattr(config, opname, ["ERROR", 0, 0])
                raise NFS4Error(error)
            else:
                inc = self.increment_error_count(opname, ceiling)
                log_41.debug("ERROR: %d check_opsconfig incrementor: %d "
                             "ceiling:%d)" % (error, inc, ceiling))
                if inc == 0:
                    raise NFS4Error(error)
        else:
            # This shouldn't happen
            raise RuntimeError("Unknown config messagetype")

    def check_utf8str_cs(self, str):
        # STUB - raises NFS4Error if appropriate.
        # Can be NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME
        pass

    def check_utf8str_cis(self, str):
        # STUB
        pass

    def check_utf8str_mixed(self, str):
        # STUB
        pass

    def check_component(self, str):
        # XXX Want to look at config if interpret dots
        # STUB
        self.check_utf8str_cs(str)
        if not str:
            raise NFS4Error(NFS4ERR_INVAL, tag="Empty component")
        if '/' in str:
            raise NFS4Error(NFS4ERR_BADCHAR)

    def op_compound(self, args, cred):
        env = CompoundState(args, cred)
        env.is_ds = self.is_ds
        # Check for problems with the compound itself
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
        opnames = []
        for arg in args.argarray:
            opname = nfs_opnum4.get(arg.argop, 'op_illegal')
            log_41.info("*** %s (%d) ***" % (opname, arg.argop))
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
            opnames.append(opname.lower()[3:])
            status = result.status
            if status != NFS4_OK:
                break
        log_41.info("Replying.  Status %s (%d)" % (nfsstat4[status], status))
        client_addr = '%s:%s' % cred.connection._s.getpeername()[:2]
        self.summary.show_op('handle v4.1 %s' % client_addr,
                             opnames, status)
        return env

    def delete_session(self, session, sessionid):
        log_41.info("delete_session REMOVE SESSION")
        del self.sessions[sessionid]
        session.client.sessions.remove(session)

    def error_set_session(self, session, sessionid, err):
        if (err == NFS4ERR_BADSESSION or err == NFS4ERR_DEADSESSION):
            self.delete_session(session, sessionid)
        raise NFS4Error(err)

    def op_sequence(self, arg, env):
        """
        See draft22 2.10.4
        """
        if env.index != 0:
            return encode_status(NFS4ERR_SEQUENCE_POS)
        session = self.sessions.get(arg.sa_sessionid, None)
        if session is None:
            return encode_status(NFS4ERR_BADSESSION)

        # We have a session. Check for injected errors
        try:
            self.check_opsconfig(env, "sequence")
        except NFS4Error as e:
            self.error_set_session(session, arg.sa_sessionid, e.status)

        # Check connection binding
        # XXX This is from old draft, needs to be checked
        connection = env.connection
        channel = session.channel_fore
        if connection not in channel.connections:
           if session.binding:
               return encode_status(NFS4ERR_CONN_NOT_BOUND_TO_SESSION)
           else:
               # Bind this connection to session, see 2.10.3.1
               channel.connections.append(connection)
        # Bounds checking
        if env.req_size + env.header_size > channel.maxrequestsize:
            return encode_status(NFS4ERR_REQ_TOO_BIG)
        if len(env.argarray) > channel.maxoperations:
            return encode_status(NFS4ERR_TOO_MANY_OPS)
        # XXX we are ignoring maxslot
        check_size(env, session.sessionid, 0, 0, 0, 0, 0)
        # seqid checking - see 2.10.5.1
        try:
            slot = channel.slots[arg.sa_slotid]
        except IndexError:
            return encode_status(NFS4ERR_BADSLOT)
        env.cache = slot.check_seqid(arg.sa_sequenceid)
        # At this point we are not allowed to return an error
        env.caching = arg.sa_cachethis
        env.session = session
        session.client.renew_lease() # Lease only renewed in non-error case
        # STUB - figure out return flags
        pass
        # return
        res = SEQUENCE4resok(session.sessionid, slot.seqid, arg.sa_slotid,
                             arg.sa_highest_slotid, channel.maxrequests, 0)
        return encode_status(NFS4_OK, res)


    def op_create_session(self, arg, env):
        # This implements draft22
        check_session(env, unique=True)
        if arg.csa_flags & ~nfs4lib.create_session_mask:
            return encode_status(NFS4ERR_INVAL,
                                 msg="Unknown bits set in flag")
        # Step 1: Client record lookup
        c = self.clients[arg.csa_clientid]
        if c is None: # STUB - or if c.frozen ???
            return encode_status(NFS4ERR_STALE_CLIENTID)
        # NOTE - had problem here where client with id=0 does some work.
        # Then server reboots, wipe state, and a different client grabs id=0.
        # Now first comes back, gets BADSESSION, so tries to create new
        # session with seqid=2, gets SEQ_MISORDERED instead of IN_USE or
        # STALE_CLIENTID

        # bypass set due to draft22 line 27338
        c.protection.deny(env, OP_CREATE_SESSION, bypass_ssv=(not c.confirmed))
        # Step 2: Sequence id processing
        env.cache = c.session_replay.check_seqid(arg.csa_sequence)
        # Step 3: Client ID confirmation
        if not c.confirmed:
            # STUB - use matching function here???
            if env.principal != c.principal:
                return encode_status(NFS4ERR_CLID_INUSE)
            else:
                c.confirmed = True
                # STUB - need to purge state of any previous, and
                # adjust ClientList appropriately
        # Go through args and use/adjust them
        session = SessionRecord(c, arg)
        connection = env.connection
        channel = session.channel_fore
        cb_channel = session.channel_back
        # Set channel attrs
        fore_attrs = channel.get_attrs()
        back_attrs = cb_channel.get_attrs()
        # Bind connection
        channel.connections.append(connection)
        session.cb_prog = arg.csa_cb_program
        # STUB - setting flags
        # Establish backchannel if the client asked for one
        flags = 0
        if arg.csa_flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN:
            try:
                self.cb_null(session.cb_prog, connection, credinfo=None)
                flags |= CREATE_SESSION4_FLAG_CONN_BACK_CHAN
                cb_channel.connections.append(connection)
            except rpc.RPCError as e:
                log_41.warn("cb_null failed with %r, no backchannel created", e)
                # STUB: backchannel is down: set sequence bits, disable layouts, etc.
                pass
        # Attach to global lists
        c.sessions.append(session) # XXX Is this needed?
        self.sessions[session.sessionid] = session
        # Return
        res = CREATE_SESSION4resok(session.sessionid, arg.csa_sequence,
                                   flags, fore_attrs, back_attrs)
        return encode_status(NFS4_OK, res)

    def op_set_ssv(self, arg, env):
        # This implements draft26
        # SSV originally stood for "Secret Session Verifier"
        check_session(env)
        protect = env.session.client.protection
        if protect.type != SP4_SSV:
            # Per draft26 18.47.3
            return encode_status(NFS4ERR_INVAL,
                                 msg="Did not request SP4_SSV protection")
        # Do some argument checking
        size = protect.context.ssv_len
        if len(arg.ssa_ssv) != size:
            return encode_status(NFS4ERR_INVAL, msg="SSV size != %i" % size)
        if arg.ssa_ssv == "\0" * size:
            return encode_status(NFS4ERR_INVAL, msg="SSV==0 not allowed")
        # Now we need to compute and check digest, using SEQUENCE args
        p = nfs4lib.FancyNFS4Packer()
        p.pack_SEQUENCE4args(env.argarray[0].opsequence)
        digest = protect.context.hmac(p.get_buffer(), SSV4_SUBKEY_MIC_I2T)
        if digest != arg.ssa_digest:
            return encode_status(NFS4ERR_BAD_SESSION_DIGEST)
        # OK, it checks, so set new ssv
        protect.context.set_ssv(arg.ssa_ssv)
        # Now create new digest using SEQUENCE result
        p.reset()
        p.pack_SEQUENCE4res(env.results[0].switch)
        digest = protect.context.hmac(p.get_buffer(), SSV4_SUBKEY_MIC_T2I)
        res = SET_SSV4resok(digest)
        return encode_status(NFS4_OK, res)

    def op_exchange_id(self, arg, env):
        # This implements draft21
        check_session(env, unique=True)
        # Check arguments for blatent errors
        if arg.eia_flags & ~nfs4lib.exchgid_mask:
            return encode_status(NFS4ERR_INVAL, msg="Unknown flag")
        if arg.eia_flags & EXCHGID4_FLAG_CONFIRMED_R:
            return encode_status(NFS4ERR_INVAL,
                                 msg="Client used server-only flag")
        if arg.eia_client_impl_id:
            impl_id = arg.eia_client_impl_id[0]
            self.check_utf8str_cis(impl_id.nii_domain)
            self.check_utf8str_cs(impl_id.nii_name)
            nfs4lib.verify_time(impl_id.nii_date)
        else:
            impl_id = None
        if arg.eia_state_protect.spa_how != SP4_NONE:
            check_secured_gss(env)
            # QUESTION - what to do about bizarre state_protect bitmaps?
            # STUB - need to check for empty sec_oid lists here?
        # Does the client believe it is updating a confirmed record?
        update = arg.eia_flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A
        verf = arg.eia_clientowner.co_verifier
        ownerid = arg.eia_clientowner.co_ownerid
        # BUG - need to hold self.clients.lock throughout this
        with self.clients.lock:
            c = self.clients[ownerid]
            if c is None:
                if update:
                    # Case 7
                    return encode_status(NFS4ERR_NOENT, msg="No such client")
                else:
                    # The simple, common case 1: a new client
                    c = self.clients.add(arg, env.principal, self.sec_flavors)
            elif not c.confirmed:
                if update:
                    # Case 7
                    return encode_status(NFS4ERR_NOENT,
                                         msg="Client not confirmed")
                else:
                    # Case 4
                    self.clients.remove(c.clientid)
                    c = self.clients.add(arg, env.principal, self.sec_flavors)
            else: # c.confirmed == True
                # STUB - state protection is from draft13 - still valid???
                # We need to do state protection tests
                # QUESTION - what if put E_ID in must_allow list?
                # Note bypass_ssv is set due to draft21 2.4.3 line 1537
                c.protection.deny(env, OP_EXCHANGE_ID, bypass_ssv=True)
                if update:
                    if c.verifier != verf:
                        # Case 8
                        return encode_status(NFS4ERR_NOT_SAME,
                                             msg="Verifier mismatch")
                    elif c.principal != env.principal:
                        # Case 9
                        return encode_status(NFS4ERR_PERM,
                                             msg="Principal mismatch")
                    else:
                        # Case 6 - update
                        c.update(arg, env.principal)
                elif c.principal != env.principal:
                    # Case 3
                    # STUB - need to check state
                    return encode_status(NFS4ERR_CLID_INUSE,
                                         msg="Principal mismatch")
                elif c.verifier != verf:
                    # Case 5
                    # Confirmed client reboot: this is the hard case
                    # STUB need to retain and pass state around
                    # Need to freeze old client, and delete state once
                    # new is confirmed
                    self.client_reboot(c) # STUB - remove state
                    self.clients.remove(c.clientid)
                    c = self.clients.add(arg, env.principal, self.sec_flavors)
                    # QUESTION - what happens if still processing request
                    # from previous client incarnation?
                else: # c.verifier == verf
                    # Case 2
                    pass
        # STUB - we are mostly ignoring arg.eia_flags for the moment
        flags = 0
        if self.is_mds:
            flags |= EXCHGID4_FLAG_USE_PNFS_MDS
        else:
            flags |= EXCHGID4_FLAG_USE_NON_PNFS
        if self.is_ds:
            flags |= EXCHGID4_FLAG_USE_PNFS_DS
        if c.confirmed:
            flags |= EXCHGID4_FLAG_CONFIRMED_R
            seq = 0 # value must be ignored by client per draft22 line 27043
        else:
            # For an ancient draft I marked this as buggy in the replay case.
            # I don't see anything wrong now.
            seq = inc_u32(c.session_replay.seqid)
        res = EXCHANGE_ID4resok(c.clientid, seq, flags,
                                c.protection.rv(arg.eia_state_protect),
                                self.config._owner, self.config.scope,
                                [self.config.impl_id])
        return encode_status(NFS4_OK, res, msg="draft21")

    def client_reboot(self, c):
        # STUB - locking?
        for sess in c.sessions:
            del self.sessions[sess.sessionid]
        c.rebooted()

    def draft10_op_bind_conn_to_session(self, arg, env):
        def bind_to_channels(dir):
            """Bind connection to given channels, returning which were done"""
            if dir in (CDFC4_FORE, CDFC4_FORE_OR_BOTH):
                session.channel_fore.bind(connection)
                if session.client.config.allow_bind_both:
                    session.channel_back.bind(connection)
                    return CDFS4_BOTH
                return CDFS4_FORE
            if dir in (CDFC4_BACK, CDFC4_BACK_OR_BOTH):
                session.channel_back.bind(connection)
                if session.client.config.allow_bind_both:
                    session.channel_fore.bind(connection)
                    return CDFS4_BOTH
                return CDFS4_BACK
            # Currently, will never get here, as will register as XDR error
            raise NFS4Error(NFS4ERR_INVAL)

        # STUB XXX do size checking
        if len(env.argarray) != 1:
            # QUESTION what is correct error return here?
            return encode_status(NFS4ERR_INVAL)
        session = self.sessions.get(arg.bctsa_sessid, None)
        if session is None:
            return encode_status(NFS4ERR_BADSESSION)
        connection = env.connection
        hash_funct = session.binding # BUG - this is from draft10
        if hash_funct is None:
            # This is the easy case.  We just accept anything.
            if arg.bctsa_digest:
                # QUESTION _INVAL or _BAD_SESSION_DIGEST also possible
                return encode_status(NFS4ERR_CONN_BINDING_NOT_ENFORCED,
                                     msg="Expected zero length digest")
            if arg.bctsa_step1 is False:
                return encode_status(NFS4ERR_INVAL, msg="Expected step1==True")
            dir = bind_to_channels(arg.bctsa_dir)
            nonce = session.get_nonce(connection, [arg.bctsa_nonce])
            # STUB this should be a session method
            del session.nonce[connection]
            res = BIND_CONN_TO_SESSION4resok(session.sessionid, False, dir,
                                             False, nonce, "")
        elif arg.bctsa_step1 is True:
            # Client has initiated the BIND
            p = nfs4lib.FancyNFS4Packer()
            p.pack_bctsr_digest_input4(bctsr_digest_input4(arg.bctsa_sessid,
                                                           arg.bctsa_nonce, 0))
            digest = hmac.new(session.ssv, p.get_buffer(), hash_funct).digest()
            if digest != arg.bctsa_digest:
                return encode_status(NFS4ERR_BAD_SESSION_DIGEST)
            # STUB - XXX need config so can choose not to challenge
            nonce = session.get_nonce(connection, [arg.bctsa_nonce])
            p.reset()
            p.pack_bctsr_digest_input4(bctsr_digest_input4(arg.bctsa_sessid,
                                                           nonce, 0))
            digest = hmac.new(session.ssv, p.get_buffer(), hash_funct).digest()
            res = BIND_CONN_TO_SESSION4resok(session.sessionid, True,
                                             CDFS4_BOTH, False, nonce, digest)
        else:
            # Client is responding to server's challenge
            try:
                # STUB XXX this should be a session method
                old_s_nonce, old_c_nonce = session.nonce[connection]
            except KeyError:
                return encode_status(NFS4ERR_INVAL,
                                     msg="server has no record of step1")
            if old_c_nonce == arg.bctsa_nonce:
                return encode_status(NFS4ERR_INVAL, msg="Client reused nonce")
            p = nfs4lib.FancyNFS4Packer()
            p.pack_bctsr_digest_input4(bctsr_digest_input4(arg.bctsa_sessid,
                                                           arg.bctsa_nonce,
                                                           old_s_nonce))
            digest = hmac.new(session.ssv, p.get_buffer(), hash_funct).digest()
            if digest != arg.bctsa_digest:
                return encode_status(NFS4ERR_BAD_SESSION_DIGEST)
            # Finally, actually bind the connection
            dir = bind_to_channels(arg.bctsa_dir)
            nonce = session.get_nonce(connection, [arg.bctsa_nonce])
            # STUB this should be a session method
            del session.nonce[connection]
            p.reset()
            p.pack_bctsr_digest_input4(bctsr_digest_input4(arg.bctsa_sessid,
                                                           nonce, old_s_nonce))
            digest = hmac.new(session.ssv, p.get_buffer(), hash_funct).digest()
            res = BIND_CONN_TO_SESSION4resok(session.sessionid, False,
                                             dir, False, nonce, digest)
        return encode_status(NFS4_OK, res)

    def op_putrootfh(self, arg, env):
        check_session(env)
        # STUB - do WRONGSEC checking
        env.set_cfh(self.root)
        return encode_status(NFS4_OK)

    def op_secinfo_no_name(self, arg, env):
        check_session(env)
        # xxx add gss support
        secinfo4_list = [ secinfo4(rpc.AUTH_SYS) ]
        res = SECINFO_NO_NAME4res(NFS4_OK, secinfo4_list)
        return encode_status(NFS4_OK, res)

    # op_putpubfh SHOULD be the same as op_putrootfh
    # See draft23, section 18.20.3, line 25005
    op_putpubfh = op_putrootfh

    def op_lookup(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.check_dir()
        name = arg.objname
        self.check_component(name)
        env.cfh.lock.acquire()
        try:
            obj = env.cfh.lookup(name, env.session.client, env.principal)
        finally:
            env.cfh.lock.release()
        if obj is None:
            return encode_status(NFS4ERR_NOENT)
        env.set_cfh(obj)
        return encode_status(NFS4_OK)

    def op_lookupp(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.check_dir()
        env.cfh.lock.acquire()
        try:
            obj = env.cfh.lookup_parent(env.session.client, env.principal)
        finally:
            env.cfh.lock.release()
        env.set_cfh(obj)
        return encode_status(NFS4_OK)

    def op_putfh(self, arg, env):
        check_session(env)
        obj = self.fh2obj(arg.object)
        if obj.fh != arg.object:
            log_41.error("\nobj.fh = %r\nwanted fh = %r" % (obj.fh, arg.object))
        env.set_cfh(obj)
        return encode_status(NFS4_OK)

    def op_getfh(self, arg, env):
        check_session(env)
        check_cfh(env)
        # We don't need to grab env.cfh.lock, since .fh is static
        fh = env.cfh.fh
        res = GETFH4resok(fh)
        return encode_status(NFS4_OK, res)

    def op_savefh(self, arg, env):
        check_cfh(env)
        env.sfh = env.cfh
        env.sid = env.cid
        return encode_status(NFS4_OK)

    def op_restorefh(self, arg, env):
        if env.sfh is None:
            raise NFS4Error(NFS4ERR_RESTOREFH)
        env.cfh = env.sfh
        env.cid = env.sid
        return encode_status(NFS4_OK)

    def op_create(self, arg, env):
        check_session(env)
        check_cfh(env)
        dir = env.cfh
        dir.check_dir()
        kind = arg.objtype
        if kind.type not in (NF4DIR, NF4LNK, NF4BLK, NF4CHR, NF4SOCK, NF4FIFO):
            return encode_status(NFS4ERR_BADTYPE)
        self.check_component(arg.objname)
        if kind.type == NF4LNK:
            self.check_utf8str_cs(arg.objtype.linkdata)
        dir.lock.acquire_write()
        try:
            old_change = dir.fattr4_change
            if dir.exists(arg.objname):
                return encode_status(NFS4ERR_EXIST)
            obj, bitmask = dir.create(arg.objname, env.principal, kind,
                                      arg.createattrs)
            new_change = dir.fattr4_change
            obj.sync()
            dir.sync()
        finally:
            dir.lock.release()
        env.cfh = obj
        env.cid = nfs4lib.state00
        cinfo = change_info4(True, old_change, new_change)
        res = CREATE4resok(cinfo, bitmask)
        return encode_status(NFS4_OK, res)

    def op_getattr(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.lock.acquire()
        try:
            attr_dict = self.get_attributes(env.cfh, arg.attr_request)
        finally:
            env.cfh.lock.release()
        return encode_status(NFS4_OK, GETATTR4resok(attr_dict))

    def op_write(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        if arg.offset + len(arg.data) > 0x3ffffffe: # STUB - arbitrary value
            return encode_status(NFS4ERR_INVAL)
        with find_state(env, arg.stateid) as state:
            state.has_permission(OPEN4_SHARE_ACCESS_WRITE)
            state.mark_writing()
            try:
                count = env.cfh.write(arg.data, arg.offset, env.principal)
                # BUG - need to fix fs locking
                how = env.cfh.sync(arg.stable)
            finally:
                state.mark_done_writing()
        res = WRITE4resok(count, how, self.verifier)
        return encode_status(NFS4_OK, res)

    def op_read(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        with find_state(env, arg.stateid, allow_bypass= \
                            env.session.client.config.allow_stateid1) as state:
            state.has_permission(OPEN4_SHARE_ACCESS_READ)
            state.mark_reading()
            try:
                # BUG - need to fix fs locking
                data = env.cfh.read(arg.offset, arg.count, env.principal)
                eof = (arg.offset + len(data)) >= env.cfh.fattr4_size
            finally:
                state.mark_done_reading()
        res = READ4resok(eof, data)
        return encode_status(NFS4_OK, res)

    def op_open(self, arg, env):
        self.check_opsconfig(env, "open")
        check_session(env)
        check_cfh(env)
        # Per draft22 8.8, arg.seqid and arg.owner.clientid are ignored
        arg.owner.clientid = env.session.client.clientid

        claim_type = arg.claim.claim
        if claim_type != CLAIM_NULL and arg.openhow.opentype == OPEN4_CREATE:
            return encode_status(NFS4ERR_INVAL,
                                 msg="OPEN4_CREATE not compatible with %s" %
                                 open_claim_type4[claim_type])
        # emulate switch(claim_type)
        try:
            func = getattr(self,
                           "open_%s" % open_claim_type4[claim_type].lower())
        except AttributeError:
            return encode_status(NFS4ERR_NOTSUPP, msg="Unsupported claim type")
        existing, cinfo, bitmask = func(arg, env)
        # existing now points to file we want to open
        if existing is None:
            return encode_status(NFS4ERR_NOENT)
        existing.verify_file(notelink=True) # Raise _ISDIR, _SYMLINK, or _INVAL
        log_41.debug("OPEN - fh = %r" % existing.fh)
        sid, deleg, flags = self.open_file(existing, arg.owner,
                                    arg.share_access, arg.share_deny)
        env.set_cfh(existing, sid)
        if env.session.client.config.debug_state:
            log_41.info("+++ client(id=%i).state = %r" %
                        (env.session.client.clientid, env.session.client.state))
        res = OPEN4resok(sid, cinfo, flags, bitmask, deleg)
        return encode_status(NFS4_OK, res)

    def open_claim_null(self, arg, env):
        """Simulated switch function from op_open that handles CLAIM_NULL"""
        bitmask = 0
        # cfh holds dir, claim.file holds name
        if not env.cfh.isdir:
            raise NFS4Error(NFS4ERR_NOTDIR)
        self.check_component(arg.claim.file) # XXX Done as part of lookup?
        # BUG - file locking needs to be fixed
        old_change = env.cfh.fattr4_change
        existing = env.cfh.lookup(arg.claim.file, env.session.client,
                                  env.principal)
        if arg.openhow.opentype == OPEN4_CREATE:
            # STUB - all sort of new stuff to add here
            if existing is None:
                if arg.openhow.mode == EXCLUSIVE4:
                    existing, bitmask = env.cfh.create(arg.claim.file,
                                                       env.principal,
                                                       NF4REG, {})
                    existing.createverf = arg.openhow.createverf
                elif arg.openhow.mode == EXCLUSIVE4_1:
                    existing, bitmask = env.cfh.create(arg.claim.file,
                                                       env.principal,
                                                       NF4REG,
                                                       arg.openhow.cva_attrs)
                    existing.createverf = arg.openhow.cva_verf
                else:
                    existing, bitmask = env.cfh.create(arg.claim.file,
                                                       env.principal,
                                                       NF4REG,
                                                       arg.openhow.createattrs)
            else:
                if arg.openhow.mode == GUARDED4:
                    raise NFS4Error(NFS4ERR_EXIST)
                elif arg.openhow.mode == UNCHECKED4:
                    # Use existing, ignore createattrs
                    # (except for truncation)
                    existing.verify_file()
                    if arg.openhow.createattrs.get(FATTR4_SIZE, None) == 0:
                        bitmask = existing.set_attrs({FATTR4_SIZE: 0},
                                                     env.principal)
                else:
                    # arg.openhow.mode == EXCLUSIVE4
                    # Use existing if verifiers match
                    if arg.openhow.createverf != existing.createverf:
                        raise NFS4Error(NFS4ERR_EXIST)
        else: # arg.openhow.opentype == OPEN4_NOCREATE:
            if existing is None:
                raise NFS4Error(NFS4ERR_NOENT)
        existing.sync()
        env.cfh.sync()
        new_change = env.cfh.fattr4_change
        cinfo = change_info4(True, old_change, new_change)
        return existing, cinfo, bitmask
        # XXX before rewrite was a BUG race here until we grab state lock

    def open_claim_fh(self, arg, env):
        """Simulated switch function from op_open that handles CLAIM_FH"""
        if not env.cfh.isfile:
            raise NFS4Error(NFS4ERR_INVAL, tag="expected cfh to be a file")
        existing = env.cfh
        # Build a somewhat pointless cinfo
        parent = existing.lookup_parent(env.session.client, env.principal)
        change = parent.fattr4_change
        cinfo = change_info4(True, change, change)
        return existing, cinfo, 0

    def grant_delegation(self, open_state, file, access):
        # STUB
        # Do we grant a new delegation? Look at DELEG, BYTE, and SHARE.
        # Also, consider new 4.1 access flags
        # STUB - only consider a read deleg
        if access & OPEN4_SHARE_ACCESS_WRITE:
            return open_delegation4(OPEN_DELEGATE_NONE)
        #if file.state[BYTE].test_lock(xxx):
        #    return open_delegation4(OPEN_DELEGATE_NONE)
        entry = file.state.grant_delegation(open_state, access)
        if entry is None:
            return open_delegation4(OPEN_DELEGATE_NONE)
        else:
            # STUB
            ace = nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                          ACE4_GENERIC_EXECUTE |
                          ACE4_GENERIC_WRITE | ACE4_GENERIC_READ,
                          "EVERYONE@")
            deleg = open_read_delegation4(entry.get_id(), False, ace)
            return open_delegation4(entry.deleg_type, deleg)

    def open_file(self, file, owner, access, deny):
        """Return stateid"""
        client = self.clients[owner.clientid]
        with file.state:
            # Want to do the share test before recall to avoid for example
            # recalling read delegations if file was originally OPENed
            # with DENY_WRITE
            # STUB - all sorts of flags we are ignoring
            file.state.test_share(access, deny)
            file.state.recall_conflicting_delegations(self, client,
                                                      access, deny)
            open_state = file.state.add_share(client, owner.owner, access, deny)
            sid = open_state.get_id()
            deleg = self.grant_delegation(open_state, file, access)
            # STUB - this needs to be thought through
            # what should it return, how should it interact with delegations,
            # where should it be in relation to above code?
            if self.is_mds:
                file.layout_open_hook()
        return sid, deleg, 0

    def get_attributes(self, obj, attrs, ignore=True):
        # XXX This really should be a FSObject method, but having trouble
        # figuring how to deal with server-wide attributes.
        if type(attrs) == int:
            attrs = nfs4lib.bitmap2list(attrs)
        ret_dict = {}
        info = nfs4lib.attr_info
        for attr in attrs:
            if attr not in info:
                # Ignore unknown attributes
                log_41.info("Skipping unknown attr: %s" % (attr,))
                continue
            if not info[attr].readable:
                # XXX How deal with write-only attrs?
                log_41.info("Skipping write only attr: %s" % (attr,))
                continue
            # Attributes hide in different places, call the place 'base'
            if info[attr].from_fs:
                base = obj.fs
            elif info[attr].from_serv:
                base = self
            else:
                base = obj
            name = "fattr4_%s" % nfs4lib.attr_name(attr)
            if hasattr(base, name) and (obj.fs.fattr4_supported_attrs & 1<<attr): # STUB we should be able to remove hasattr
                ret_dict[attr] = getattr(base, name)
            else:
                if ignore:
                    # Must ignore for GETATTR (and READDIR) per 15.1
                    log_41.info("ignored attr %s" % (name,))
                    continue
                else:
                    # This is for VERIFY/NVERIFY
                    log_41.info("attr NOT SUPP %s" % (name,))
                    raise NFS4Error(NFS4ERR_ATTRNOTSUPP)
        obj.fattr4_rdattr_error = NFS4_OK # XXX STUB Handle correctly
        return ret_dict

    def op_access(self, arg, env):
        check_session(env)
        check_cfh(env)
        supported = 0
        access = 0
        for flag, name in nfs4lib.access_flags.items():
            # Was it asked for?
            if not (flag & arg.access):
                continue
            # Is it supported?
            access_funct = getattr(env.cfh, name.lower(), None)
            if access_funct is None:
                continue
            supported |= flag
            # Is it allowed?
            if access_funct(env.principal):
                access |= flag
        res = ACCESS4resok(supported, access)
        return encode_status(NFS4_OK, res)

    def op_readdir(self, arg, env):
        def find_size(e):
            # Find size of xdr encoded response
            p = nfs4lib.FancyNFS4Packer()
            p.pack_entry4(e)
            return len(p.get_buffer())

        offset = 3 # index offset used to avoid reserved cookies
        check_session(env)
        check_cfh(env)
        env.cfh.check_dir()
        if arg.cookie in (1, 2) or \
               (arg.cookie==0 and arg.cookieverf != "\0" * 8):
            return encode_status(NFS4ERR_BAD_COOKIE)
        objlist, verifier = env.cfh.readdir(arg.cookieverf, env.session.client, env.principal) # (name, obj) pairs
        # STUB - think through rdattr_error handling
        if arg.cookie == 0:
            i = 0
        else:
            i = arg.cookie - offset + 1
        eof = False
        entrylist = []
        size = 16 # Size of packing an empty list into READDIR4resok
        while True:
            try:
                name, obj = objlist[i]
            except IndexError:
                eof = True
                break
            e = entry4(i+offset, name,
                       self.get_attributes(obj, arg.attr_request), [])
            size += find_size(e)
            if size > arg.maxcount:
                if not entrylist:
                    return encode_status(NFS4ERR_TOOSMALL)
                break
            entrylist.append(e)
            i += 1
        log_41.debug("ENTRIES: %r" % entrylist)
        res = READDIR4resok(verifier, dirlist4(entrylist, eof))
        return encode_status(NFS4_OK, res)

    def op_setattr(self, arg, env):
        try:
            check_session(env)
            check_cfh(env)
            attrs = arg.obj_attributes
            if FATTR4_SIZE not in attrs:
                bitmap = env.cfh.set_attrs(attrs, env.principal)
            else:
                with find_state(env, arg.stateid) as state:
                    state.has_permission(OPEN4_SHARE_ACCESS_WRITE)
                    # BUG fs locking
                    state.mark_writing()
                try:
                    bitmap = env.cfh.set_attrs(attrs, env.principal)
                finally:
                    state.mark_done_writing()
            return encode_status(NFS4_OK, bitmap)
        except NFS4Error as e:
            # SETATTR failure does not encode just status
            return encode_status(e.status, e.attrs)

    def op_destroy_session(self, arg, env):
        # STUB - need to deal with other threads using session
        session = self.sessions.get(arg.dsa_sessionid, None)
        if session is None:
            return encode_status(NFS4ERR_BADSESSION)
        if session == env.session:
            # This must be last op in compound
            if env.index != len(env.argarray) - 1:
                return encode_status(NFS4ERR_INVAL) # QUESTION - what error?
        # STUB - need to think through any locking issues
        del self.sessions[arg.dsa_sessionid]
        session.client.sessions.remove(session)
        return encode_status(NFS4_OK)

    def op_remove(self, arg, env):
        check_session(env)
        check_cfh(env)
        self.check_component(arg.target)
        dir = env.cfh
        dir.check_dir()
        # BUG fs locking
        obj = dir.lookup(arg.target, env.session.client, env.principal)
        if obj is None:
            return encode_status(NFS4ERR_NOENT)
        old_change = dir.fattr4_change
        with obj.state:
            obj.state.test_share(OPEN4_SHARE_ACCESS_WRITE,
                                 error=NFS4ERR_FILE_OPEN)
            dir.unlink(arg.target, env.principal) # Why is this under lock?
        new_change = dir.fattr4_change
        dir.sync()
        cinfo = change_info4(True, old_change, new_change)
        res = REMOVE4resok(cinfo)
        return encode_status(NFS4_OK, res)

    def op_close(self, arg, env):
        check_session(env)
        check_cfh(env)
        # arg.seqid value is ignored
        env.cfh.verify_file()
        with find_state(env, arg.open_stateid, allow_0=False) as state:
            # BUG - need to fix fs locking
            env.cfh.close()
            if self.is_mds:
                env.cfh.layout_close_hook()
            state.close()
            id = state.get_id()
        return encode_status(NFS4_OK, id)

    def op_commit(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        with env.cfh.state: # Is this necessary?
            # BUG fs locking
            env.cfh.sync()
        res = COMMIT4resok(self.verifier)
        return encode_status(NFS4_OK, res)

    def op_link(self, arg, env):
        check_session(env)
        check_cfh(env)
        check_sfh(env)
        env.cfh.check_dir()
        env.sfh.verify_file()
        self.check_component(arg.newname)
        env.cfh.lock.acquire_write()
        try:
            if env.cfh.exists(arg.newname):
                return encode_status(NFS4ERR_EXIST)
            old_change = env.cfh.fattr4_change
            env.cfh.link(arg.newname, env.sfh, env.principal)
            new_change = env.cfh.fattr4_change
        finally:
            env.cfh.lock.release()
        res = LINK4resok(change_info4(True, old_change, new_change))
        return encode_status(NFS4_OK, res)

    def op_readlink(self, arg, env):
        check_session(env)
        check_cfh(env)
        if env.cfh.fattr4_type != NF4LNK:
            return encode_status(NFS4_INVAL, msg="cfh type was %i" % i)
        res = READLINK4resok(env.cfh.linkdata)
        return encode_status(NFS4_OK, res)

    def op_nverify(self, arg, env):
        check_session(env)
        check_cfh(env)
        try:
            attrreq = arg.obj_attributes
            if FATTR4_RDATTR_ERROR in attrreq:
                raise NFS4Error(NFS4ERR_INVAL)
            attrvals = self.get_attributes(env.cfh, attrreq.keys(), ignore=False)
        except NFS4Error as e:
            return encode_status(e.code)
        if attrvals == attrreq:
            return encode_status(NFS4ERR_SAME)
        else:
            return encode_status(NFS4_OK)

    def op_verify(self, arg, env):
        check_session(env)
        check_cfh(env)
        try:
            attrreq = arg.obj_attributes
            if FATTR4_RDATTR_ERROR in attrreq:
                raise NFS4Error(NFS4ERR_INVAL)
            attrvals = self.get_attributes(env.cfh, attrreq.keys(), ignore=False)
        except NFS4Error as e:
            return encode_status(e.code)
        if attrvals != attrreq:
            return encode_status(NFS4ERR_NOT_SAME)
        else:
            return encode_status(NFS4_OK)

    def op_rename(self, arg, env):
        check_session(env)
        check_cfh(env)
        check_sfh(env)
        env.cfh.check_dir()
        env.sfh.check_dir()
        self.check_component(arg.oldname)
        self.check_component(arg.newname)
        if not nfs4lib.test_equal(env.sfh.fattr4_fsid, env.cfh.fattr4_fsid,
                                  kind="fsid4"):
            return encode_status(NFS4ERR_XDEV, msg="%r != %r" % (env.sfh.fattr4_fsid, env.cfh.fattr4_fsid))
        order = sorted(set([env.cfh, env.sfh])) # Used to prevent locking problems
        # BUG fs locking
        old_change_src = env.sfh.fattr4_change
        old_change_dst = env.cfh.fattr4_change
        src = env.sfh.lookup(arg.oldname, env.session.client, env.principal, follow_mount=False)
        if src is None:
            return encode_status(NFS4ERR_NOENT)
        dst = env.cfh.lookup(arg.newname, env.session.client, env.principal, follow_mount=False)
        if dst is not None:
            if dst.fattr4_fileid == src.fattr4_fileid:
                # They are the same file, do nothing
                res = RENAME4resok(change_info4(True, old_change_src,
                                                old_change_src),
                                   change_info4(True, old_change_dst,
                                                old_change_dst))
                return encode_status(NFS4_OK, res)
            compatible = dst.fattr4_type == src.fattr4_type
            if dst.isdir and not dst.isempty:
                # BUG there is a race here, since we don't have any
                # lock on dst
                compatible = False
            if not compatible:
                return encode_status(NFS4ERR_EXIST)
            with dst.state:
                dst.state.test_share(OPEN4_SHARE_ACCESS_WRITE,
                                     error=NFS4ERR_FILE_OPEN)
                env.cfh.unlink(arg.newname, env.principal)
        # We need to link obj in new spot, then unlink in old
        # We don't do it in the other order to prevent refcnt going to zero
        env.cfh.link(arg.newname, src, env.principal)
        env.sfh.unlink(arg.oldname, env.principal)
        new_change_src = env.sfh.fattr4_change
        new_change_dst = env.cfh.fattr4_change
        res = RENAME4resok(change_info4(True, old_change_src, new_change_src),
                           change_info4(True, old_change_dst, new_change_dst))
        return encode_status(NFS4_OK, res)

    def _getlockend(self, offset, length):
        if length == 0:
            raise NFS4Error(NFS4ERR_INVAL)
        if length == 0xffffffffffffffff:
            end = length
        else:
            end = length + offset
            if end > 0xffffffffffffffff: # XXX Should this be 0x100...???
                raise NFS4Error(NFS4ERR_INVAL)
            end -= 1
        return end

    def op_lock(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        if arg.reclaim:
            # STUB
            raise NFS4Error(NFS4ERR_NO_GRACE)
        end = self._getlockend(arg.offset, arg.length)
        # seqid and embedded clientid fields are ignored
        try:
            if arg.new_lock_owner:
                lock_owner = arg.open_owner.lock_owner.owner
                with find_state(env, arg.open_stateid, allow_0=False) as state:
                    state = state.create_lockowner(lock_owner)
                    # XXX Do we need to advance open stateid?
                    state.add_lock(arg.locktype, arg.offset, end)
                    # XXX Should we advance lockowner stateid?
                    stateid = state.get_id()
            else:
                with find_state(env, arg.lock_stateid, allow_0=False) as state:
                    state.add_lock(arg.locktype, arg.offset, end)
                    stateid = state.get_id()
        except NFS4Error as e:
            return encode_status(e.status, denied=e.lock_denied)
        l4resok = LOCK4resok(stateid)
        return encode_status(NFS4_OK, l4resok)

    def op_lockt(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        end = self._getlockend(arg.offset, arg.length)
        try:
            with env.cfh.state:
                env.cfh.state.test_lock(env.session.client, arg.owner.owner,
                                        arg.locktype, arg.offset, end)
        except NFS4Error as e:
            return encode_status(e.status, denied=e.lock_denied)
        return encode_status(NFS4_OK)

    def op_locku(self, arg, env):
        check_session(env)
        check_cfh(env)
        env.cfh.verify_file()
        end = self._getlockend(arg.offset, arg.length)
        with find_state(env, arg.lock_stateid, allow_0=False) as state:
            state.remove_lock(arg.locktype, arg.offset, end)
            stateid = state.get_id()
        return encode_status(NFS4_OK, stateid)

    def op_delegreturn(self, arg, env):
        self.check_opsconfig(env, "delegreturn")
        check_session(env)
        check_cfh(env)
        with find_state(env, arg.deleg_stateid, allow_0=False) as state:
            state.delegreturn()
        return encode_status(NFS4_OK)

    def op_getdevicelist(self, arg, env): # STUB
        check_session(env)
        check_cfh(env)
        if arg.gdla_maxdevices == 0:
            return encode_status(NFS4ERR_INVAL)
        fs = env.cfh.fs
        # STUB Deal with whole cookie thing
        kind = arg.gdla_layout_type
        verf = (arg.gdla_cookieverf if arg.gdla_cookie else None)
        list = fs.get_devicelist(kind, verf)
        # NOTE - the devid's must be globally unique per type.  The obvious
        # approach is for the server to add a uniquefier to shortened IDs
        # returned from the fs.  This doesn't work, though, since the fs
        # (the block in particular) requires devid be embedded in opaque
        # blobs, so that fs needs to know full devid sent to client.
        # Best approach seems to be for fs to query server for a new
        # devid to use, which is done at mount.
        new_cookie = arg.gdla_cookie + arg.gdla_maxdevices
        new_verf = "stubverf"
        slice = list[arg.gdla_cookie: new_cookie]
        res = GETDEVICELIST4resok(new_cookie, new_verf,
                                  [dev.devid for dev in slice],
                                  new_cookie >= len(list))
        return encode_status(NFS4_OK, res)

    def op_getdeviceinfo(self, arg, env): # STUB
        # STUB - ignoring notifications
        check_session(env)
        device = self.find_device(arg.gdia_device_id, arg.gdia_layout_type)
        if device is None:
            return encode_status(NFS4ERR_NOENT)
        maxcount = arg.gdia_maxcount
        body = (device.address_body if maxcount else "")
        address = device_addr4(arg.gdia_layout_type, body)
        if maxcount:
            # Check that we don't exceed maxcount
            p = nfs4lib.FancyNFS4Packer()
            p.pack_device_addr4(address)
            buflen = len(p.get_buffer())
            if buflen > maxcount:
                return encode_status(NFS4ERR_TOOSMALL, gdir_mincount = buflen)
        res = GETDEVICEINFO4resok(address, 0)
        return encode_status(NFS4_OK, res)

    def op_layoutget(self, arg, env): # STUB
        try:
            check_session(env)
            check_cfh(env)
            if arg.loga_length == 0:
                return encode_status(NFS4_INVAL, msg="length == 0")
            if arg.loga_length != 0xffffffffffffffff:
                if arg.loga_length + arg.loga_offset > 0xffffffffffffffff:
                     return encode_status(NFS4_INVAL, msg="offset+length too big")
            if not env.session.has_backchannel:
                raise NFS4Error(NFS4ERR_LAYOUTTRYLATER)
            # STUB do state locking and check on iomode,offset,length triple
            with find_state(env, arg.loga_stateid, allow_0=False) as state:
                layout, entry = env.cfh.state.grant_layout(state, arg)
                # STUB at some point make the decision below dynamic
                return_on_close = False
                res = LAYOUTGET4resok(return_on_close, entry.get_id(), [layout])
                return encode_status(NFS4_OK, res)
        except NFS4Error as e:
            # LAYOUTGET failure does not encode just status
            if e.status == NFS4ERR_LAYOUTTRYLATER:
                return encode_status(e.status, None, False)
            raise

    def op_layoutcommit(self, arg, env): # STUB
        check_session(env)
        check_cfh(env)
        size = env.cfh.commit_layout(arg)
        if size is None:
            new_size = newsize4(False)
        else:
            new_size = newsize4(True, size)
        res = LAYOUTCOMMIT4resok(new_size)
        return encode_status(NFS4_OK, res)

    def op_layoutreturn(self, arg, env): # STUB
        # This just returns OK
        check_session(env)
        if arg.lora_layoutreturn.lr_returntype != LAYOUTRETURN4_ALL:
            check_cfh(env)
        if arg.lora_layoutreturn.lr_returntype == LAYOUTRETURN4_FILE:
            state = layoutreturn_stateid(True, arg.lrf_stateid)
        else:
            state = layoutreturn_stateid(False)
        return encode_status(NFS4_OK, state)

    def op_illegal(self, arg, env):
        return encode_status(NFS4ERR_OP_ILLEGAL)

    def ctrl_reset(self, arg):
        self.recording.reset()
        return xdrdef.sctrl_const.CTRLSTAT_OK, xdrdef.sctrl_type.resdata_t(arg.ctrlop)

    def ctrl_record(self, arg):
        self.recording.set_stamp(arg.stamp)
        self.recording.on = True
        return xdrdef.sctrl_const.CTRLSTAT_OK, xdrdef.sctrl_type.resdata_t(arg.ctrlop)

    def ctrl_pause(self, arg):
        self.recording.on = False
        return xdrdef.sctrl_const.CTRLSTAT_OK, xdrdef.sctrl_type.resdata_t(arg.ctrlop)

    def ctrl_grab(self, arg):
        queue = self.recording.queues.get(arg.stamp, None)
        if queue is None:
            return xdrdef.sctrl_const.CTRLSTAT_NOT_AVAIL, \
                   xdrdef.sctrl_type.resdata_t(arg.ctrlop, xdrdef.sctrl_type.GRABres([],[]))
        max = arg.number
        if max == 0:
            max = len(queue)
        calls = []
        replies = []
        for i in range(max):
            call, reply = queue.pop()
            if arg.dir & xdrdef.sctrl_const.DIR_CALL:
                calls.append(call)
            if arg.dir & xdrdef.sctrl_const.DIR_REPLY:
                replies.append(reply)
        #print(calls)
        #print(replies)
        grabres = xdrdef.sctrl_type.GRABres(calls, replies)
        return xdrdef.sctrl_const.CTRLSTAT_OK, \
               xdrdef.sctrl_type.resdata_t(arg.ctrlop, grab = grabres)

    def ctrl_illegal(self, arg):
        #print("ILLEGAL")
        return xdrdef.sctrl_const.CTRLSTAT_ILLEGAL, xdrdef.sctrl_type.resdata_t(arg.ctrlop)

    def op_setclientid(self, arg, env):
        return encode_status(NFS4ERR_NOTSUPP)

    def op_setclientid_confirm(self, arg, env):
        return encode_status(NFS4ERR_NOTSUPP)

    def fh2obj(self, fh):
        """Given a fh, find the appropriate FSObject"""
        log_41.log(5, "fh2obj(%r)" % fh)
        try:
            major, minor, flag, id = struct.unpack("!QQbQ", fh)
            log_41.log(5, "fh2obj - %i, %i, %i, %i = " % \
                            (major, minor, flag, id ))
            fs = self.fsid2fs((major, minor))
            log_41.log(5, "fh2obj - chooses fsid %r" % (fs.fsid,))
            obj = fs.find(id)
        except:
            raise NFS4Error(NFS4ERR_BADHANDLE)
        return obj

    def fsid2fs(self, fsid):
        return self._fsids[fsid]

    def cb_compound_async(self, args, prog, credinfo=None, pipe=None, tag=None):
        if tag is None:
            tag = "Default callback tag"
        if pipe is None:
            # BUG
            raise RuntimeError
        if credinfo is None:
            credinfo = self.default_cred
        p = nfs4lib.FancyNFS4Packer()
        c4 = CB_COMPOUND4args(tag, 1, 0, args)
        log_41.info("*" * 40)
        log_41.info("Sending CB_COMPOUND")
        log_41.info(repr(c4))
        p.pack_CB_COMPOUND4args(c4)
        # Despite RFC5661 18.36.3:
        # "The server MUST specify...an ONC RPC version number equal to 4",
        # Per the May 17, 2010 discussion on the ietf list, errataID 2291
        # indicates it should in fact be 1
        return pipe.send_call(prog, 1, 1, p.get_buffer(), credinfo)

    def cb_compound(self, *args, **kwargs):
        xid = self.cb_compound_async(*args, **kwargs)
        pipe = kwargs.get("pipe", None)
        return self.cb_listen(xid, pipe)

    def cb_listen(self, xid, pipe, timeout=10.0):
        header, data = pipe.listen(xid, timeout)
        log_41.info("Received CB_COMPOUND reply")
        log_41.info(header)
        if data:
            p = nfs4lib.FancyNFS4Unpacker(data)
            data = p.unpack_CB_COMPOUND4res()
        log_41.info(data)
        return data

    def cb_null_listen(self, xid, pipe, timeout=5.0):
        header, data = pipe.listen(xid, timeout)
        log_41.info("Received CB_NULL reply")
        log_41.info(header)
        if data:
            # log but ignore the problem
            log_41.error("Unexpected data in cb_null reply")

    def cb_null_async(self, prog, credinfo, pipe):
        log_41.info("*" * 20)
        log_41.info("Sending CB_NULL")
        # Despite RFC5661 18.36.3:
        # "The server MUST specify...an ONC RPC version number equal to 4",
        # Per the May 17, 2010 discussion on the ietf list, errataID 2291
        # indicates it should in fact be 1
        return pipe.send_call(prog, 1, 0, "", credinfo)

    def cb_null(self, prog, pipe, credinfo=None):
        """ Sends bc_null."""
        if pipe is None:
            # BUG
            raise RuntimeError
        if credinfo is None:
            credinfo = self.default_cred
        xid = self.cb_null_async(prog, credinfo, pipe)
        return self.cb_null_listen(xid, pipe)


##################################################
# The actual script handling
##################################################

def read_exports(server, opts):
    file = opts.exports
    if file.endswith(".py"):
        file = file[:-3]
    mod = __import__(file)
    mod.mount_stuff(server, opts)

def scan_options():
    from optparse import OptionParser, OptionGroup, IndentedHelpFormatter
    p = OptionParser("%prog [-r] [--bypass_checks]",
                    formatter = IndentedHelpFormatter(2, 25)
                    )
    p.add_option("-r", "--reset", action="store_true", default=False,
                 help="Reset and clear any disk-based filesystems")
    p.add_option("-v", "--verbose", action="store_true", default=False,
                 help="Print debug info to screen and enter interpreter on ^C")
    p.add_option("-s", "--show_summary", action="store_true", default=False,
                 help="Print short summary of operations")
    p.add_option("--use_block", action="store_true", default=False,
                 help="Mount a block-pnfs fs")
    p.add_option("--use_files", action="store_true", default=False,
                 help="mount a file-pnfs fs")
    p.add_option("--is_ds", action="store_true", default=False,
                 help="act as a dataserver")
    p.add_option("--exports", default="server_exports.py",
                 help="File used to determine server exports, "
                 "similar to /etc/exports")
    p.add_option("--dataservers", default="dataservers.conf",
                 help="File used to determine dataserver addresses")
    p.add_option("--port", type="int", default=2049,
                 help="Set port to listen on (2049)")

    g = OptionGroup(p, "Debug options",
                    "These affect information collected and printed.")
    g.add_option("--debug_locks", action="store_true", default=False,
                 help="Threads track locks and their state")
    p.add_option_group(g)

    opts, args = p.parse_args()
    if args:
        p.error("Unhandled argument %r" % args[0])
    return opts

if __name__ == "__main__":
    opts = scan_options()
    if opts.debug_locks:
        import locking
        locking.DEBUG = True
    S = NFS4Server(port=opts.port,
                   is_mds=opts.use_block or opts.use_files,
                   is_ds = opts.is_ds,
                   verbose = opts.verbose,
                   show_summary = opts.show_summary)
    read_exports(S, opts)
    if True:
        S.start()
    else:
        import profile
        # This doesn't work well - only looks at main thread
        profile.run('S.start()', 'profile_data')
