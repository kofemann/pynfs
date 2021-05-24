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
from nfs4commoncode import CBCompoundState, CompoundState, encode_status, encode_status_by_name
import nfs4client
import sys, traceback
from errorparser import ErrorDesc, ErrorParser

log = logging.getLogger("nfs.proxy")
log.setLevel(logging.INFO)

class NFS4Proxy(rpc.Server):
    """Implement an NFS(v4.x) proxy."""
    class Channel(object):
        def __init__(self, maxreqsz, maxrespsz, maxrespszc, maxops, maxreqs):
            self.maxrequestsize = maxreqsz
            self.maxresponsesize = maxrespsz
            self.maxresponsesize_cached = maxrespszc
            self.maxoperations = maxops
            self.maxrequests = maxreqs

    class ProxyClient(rpc.Client):
        def __init__(self, prog, version, cb_version, server, port, pipe):
            rpc.Client.__init__(self, prog, version)
            self.proxy = None
            self.prog = prog
            self.version = version
            self.dserver = server
            self.dport = port
            self.cb_prog = None
            self.cb_versions = [cb_version]
            # currently support only root (? fix ? )
            rpcsec = rpc.security.instance(rpc.AUTH_SYS)
            self.default_cred = rpcsec.init_cred(uid=0,gid=0,name="root")
            if pipe: #reuse connection
                self.pipe = pipe
            else:
                self.pipe = self.connect_to_server()

        def _check_program(self, prog):
            if self.cb_prog is not None:
                return (prog == self.cb_prog)

        def _version_range(self, prog):
            return (min(self.cb_versions), max(self.cb_versions))

        def _find_method(self, msg):
            method = getattr(self.proxy, 'handle_cb_%i' % msg.proc, None)
            if method is not None:
                return method
            return None

        def connect_to_server(self, delay=5, retries=3):
            while True:
                try:
                    server_address = (self.dserver, self.dport)
                    print(server_address)
                    pipe = self.connect(server_address)
                except:
                    traceback.print_exc(file=sys.stdout)
                    log.critical("Cannot connect to destination server %r:%r"
                                 % (self.dserver, self.dport))
                    log.critical("Retrying in %s secs..." % delay)
                    time.sleep(delay)
                    delay = delay + delay
                    retries -= 1
                    if retries < 0:
                        raise Exception
                    continue
                else:
                    return pipe

        def make_call(self, proc, data, timeout=15.0):
                xid = self.pipe.send_call(self.prog, self.version,
                                          proc, data, self.default_cred)
                header, data = self.pipe.listen(xid, timeout)
                return data

    def __init__(self, **kwargs):
        port = kwargs.pop("port")
        dport = kwargs.pop("dport")
        dserver = kwargs.pop("dserver")
        self.program = kwargs.pop("program", NFS4_PROGRAM)
        self.version = kwargs.pop("version", 4)
        self.cb_version = kwargs.pop("cb_version", 1)
        self.tag = "proxy tag"
        self.fchannel = self.Channel(34000, 34000, 1200, 8, 8)
        self.bchannel = self.Channel(4096, 4096, 0, 2, 1)
        rpc.Server.__init__(self, prog=self.program, versions=[self.version],
                            port=port)
        # we support only one server connection
        self.client = self.ProxyClient(self.program, self.version,
                                       self.cb_version,
                                       dserver, dport,
                                       None)
        self.client.proxy = self
        # load error description file
        errfile = kwargs.pop("errorfile", None)
        self.errorhandler = ErrorParser(errfile)

    def start(self):
        """Cause the server to start listening on the previously bound port"""
        try:
            rpc.Server.start(self)
        except KeyboardInterrupt:
            import sys
            sys.exit()

    def start_cb_proxy(self, program, version, client_pipe):
        # FIXME: we support only one client at a time (at least with backchannel)
        self.client.cb_prog = program
        self.cb_client = self.ProxyClient(program, version, None, None,
                                          None, client_pipe)
        self.cb_client.proxy = self

    def forward_call(self, calldata, callback=False, procedure=1,
                     timeout=15.0, retries=3):
        def get_client(callback):
            if callback:
                return self.cb_client
            return self.client
        while True:
            try:
                client = get_client(callback)
                data = client.make_call(procedure, calldata)
                return data
            except rpc.RPCTimeout:
                log.critical('-'*60)
                log.critical("RPC call forwarding failed")
                traceback.print_exc(file=sys.stdout)
                retries = retries - 1
                if retries > 0:
                    log.critical("Retrying...")
                    continue
                raise rpc.RPCTimeout

    def handle_cb_0(self, data, cred):
        return self.handle_0(data, cred, callback=True)

    def handle_cb_1(self, data, cred):
        return self.handle_1(data, cred, callback=True)

    def handle_0(self, data, cred, callback=False):
        """NULL procedure"""
        log.debug("*" * 20)
        if callback:
            log.debug("** CALLBACK **")
        log.debug("Handling NULL")
        try:
            self.forward_call(calldata="", callback=callback, procedure=0)
            return rpc.SUCCESS, ''
        except rpc.RPCTimeout:
            log.critical("Error: cannot connect to destination server")
            return rpc.GARBAGE_ARGS, None

    def handle_1(self, data, cred, callback=False):
        """COMPOUND procedure"""
        log.debug("*" * 40)
        if callback:
            log.debug("** CALLBACK **")
        log.debug("Handling COMPOUND")
        # stage 1: data in XDR as received from the client
        unpacker = nfs4lib.FancyNFS4Unpacker(data)
        if callback:
            args = unpacker.unpack_CB_COMPOUNDargs()
        else:
            args = unpacker.unpack_COMPOUND4args()
        log.debug("Client sent:")
        log.debug(repr(args))
        unpacker.done()
        # stage 2: pre-processing - data in COMPOUND4args
        # XXX: check operation, alter stuff, delay etc. etc.
        args.req_size = len(data) # BUG, need to use cred.payload_size
        if callback:
            env = CBCompoundState(args, cred)
        else:
            env = CompoundState(args, cred)
        for arg in args.argarray:
            env.index += 1
            opname = nfs_opnum4.get(arg.argop, 'op_illegal')
            log.info("*** %s (%d) ***" % (opname, arg.argop))
            # look for functions implemented by the proxy
            # that override communication
            funct = getattr(self, opname.lower(), None)
            if funct is not None and callable(funct):
                try:
                    result = funct(arg, cred, direction=0)
                except Exception:
                    log.error("Function override %s failed" % opname.lower())
            # handle error condition if specified
            error = None
            if self.errorhandler is not None:
                error = self.errorhandler.get_error(opname.lower()[3:],
                                                    arg, env)
            if error is not None:
                result = encode_status_by_name(opname.lower()[3:],
                                            int(error),
                                            msg="Proxy Rewrite Error")
                env.results.append(result)
                p = nfs4lib.FancyNFS4Packer()
                if callback:
                    res = CB_COMPOUND4res(env.results.reply.status,
                                          env.results.reply.tag,
                                          env.results.reply.results)
                    p.pack_CB_COMPOUND4res(res)
                else:
                    res = COMPOUND4res(env.results.reply.status,
                                       env.results.reply.tag,
                                       env.results.reply.results)
                    p.pack_COMPOUND4res(res)
                log.info(repr(res))
                reply = p.get_buffer()
                return rpc.SUCCESS, reply
        #stage 3: repack the data and forward to server
        packer = nfs4lib.FancyNFS4Packer()
        if callback:
            packer.pack_CB_COMPOUND4args(args)
        else:
            packer.pack_COMPOUND4args(args)
        log.debug("Proxy sent:")
        log.debug(repr(args))
        calldata = packer.get_buffer()
        try:
            ret_data = self.forward_call(calldata, callback)
        except rpc.RPCTimeout:
            log.critical("Error: cannot connect to destination server")
            return rpc.GARBAGE_ARGS, None
        # stage 4: data in XDR as returned by the server
        unpacker = nfs4lib.FancyNFS4Unpacker(ret_data)
        if callback:
            res = unpacker.unpack_CB_COMPOUND4res()
        else:
            res = unpacker.unpack_COMPOUND4res()
        log.debug("Server returned:")
        log.debug(repr(res))
        unpacker.done()
        # stage 5: post-processing - data in COMPOUND4res
        # XXX: check operation etc.
        for arg in res.resarray:
            opname = nfs_opnum4.get(arg.resop, 'op_illegal')
            log.info("*** %s (%d) ***" % (opname, arg.resop))
            # look for functions implemented by the proxy
            # that override communication
            funct = getattr(self, opname.lower(), None)
            if funct is not None and callable(funct):
                try:
                    result = funct(arg, cred, direction=1)
                except Exception:
                    log.error("Function override %s failed" % opname.lower())
        # state 6: repack and return XDR data to client
        packer = nfs4lib.FancyNFS4Packer()
        if callback:
            packer.pack_CB_COMPOUND4res(res)
        else:
            packer.pack_COMPOUND4res(res)
        log.debug("Proxy returned:")
        log.debug(repr(res))
        reply = packer.get_buffer()
        return rpc.SUCCESS, reply

# FUNCTION OVERRIDING START
# just define a function called "op_<name>(self, arg, callback)"

    def op_create_session(self, arg, cred, direction=0):
            def _adjust_channel_values(attrs, chan):
                if chan.maxrequestsize < attrs.ca_maxrequestsize:
                    attrs.ca_maxrequestsize = chan.maxrequestsize
                if chan.maxresponsesize < attrs.ca_maxresponsesize:
                    attrs.ca_maxresponsesize = chan.maxresponsesize
                if chan.maxresponsesize_cached < attrs.ca_maxresponsesize_cached:
                    attrs.ca_maxresposnesize_cached = chan.maxresponsesize_cached
                if chan.maxoperations < attrs.ca_maxoperations:
                    attrs.ca_maxoperations = chan.maxoperations
                if chan.maxrequests < attrs.ca_maxrequests:
                    attrs.ca_maxrequests = chan.maxrequests
            if direction is 0: # client to proxy
                # XXX: this might be buggy with more than one clients (?)
                self.start_cb_proxy(arg.opcreate_session.csa_cb_program,
                                    version=1, client_pipe=cred.connection)
                _adjust_channel_values(arg.opcreate_session.csa_fore_chan_attrs,
                                       self.fchannel)
                _adjust_channel_values(arg.opcreate_session.csa_back_chan_attrs,
                                       self.bchannel)
            elif direction is 1: # proxy to client
                pass
#FUNCTION OVERRIDING END

def scan_options():
    from optparse import OptionParser, OptionGroup, IndentedHelpFormatter
    p = OptionParser("%prog [--dport=<?> --port=<?>] --dserver=<?>",
                    formatter = IndentedHelpFormatter(2, 25)
                    )
    p.add_option("--dserver", dest="dserver", help="IP address to connect to")
    p.add_option("--dport", dest="dport", default="2049", type=int, help="Set port to connect to")
    p.add_option("--port", dest="port", type=int, default="2049", help="Set port to listen on (2049)")

    opts, args = p.parse_args()
    if args:
        p.error("Unhandled argument %r" % args[0])
    return opts

if __name__ == "__main__":
    opts = scan_options()
    S = NFS4Proxy(port=opts.port, dserver=opts.dserver, dport=opts.dport, errorfile="error.xml")
    if True:
        S.start()
    else:
        import profile
        # This doesn't work well - only looks at main thread
        profile.run('S.start()', 'profile_data')
