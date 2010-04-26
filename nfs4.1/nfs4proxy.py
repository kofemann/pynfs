#!/usr/bin/env python
from __future__ import with_statement
import use_local # HACK so don't have to rebuild constantly
import nfs4lib
from nfs4lib import inc_u32, NFS4Error, NFS4Replay
import rpc
from nfs4_const import *
from nfs4_type import *
from sctrl_pack import SCTRLPacker, SCTRLUnpacker
import sctrl_type, sctrl_const
import traceback, threading
from locking import Lock, Counter
import time
import hmac
import random
import struct
import collections
import logging
from nfs4commoncode import CompoundState, encode_status, encode_status_by_name
import nfs4client
import sys, traceback

log = logging.getLogger("nfs.proxy")
log.setLevel(logging.CRITICAL)

class NFS4Proxy(rpc.Server):
    """Implement an NFS(v4.x) proxy."""
    class ProxyClient(rpc.Client):
        def __init__(self, prog, version, server, port):
            rpc.Client.__init__(self, prog, version)
            self.prog = prog
            self.version = version
            self.dserver = server
            self.dport = port
            self.cb_prog = None
            self.cb_versions = [1, 4]
            # currently support only root (? fix ? )
            rpcsec = rpc.security.instance(rpc.AUTH_SYS)
            self.default_cred = rpcsec.init_cred(uid=0,gid=0,name="root")
            self.pipe = self.connect_to_server()

        def connect_to_server(self, delay=5, retries=3):
            while True:
                try:
                    server_address = (self.dserver, self.dport)
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
        self.prog = NFS4_PROGRAM
        self.versions = [4]
        self.minor_versions = [0] + [1]
        self.tag = "proxy tag"
        rpc.Server.__init__(self, prog=self.prog, versions=self.versions,
                            port=port, **kwargs)
        self.client = self.ProxyClient(self.prog, self.versions[0],
                                       dserver, dport)

    def start(self):
        """Cause the server to start listening on the previously bound port"""
        try:
            rpc.Server.start(self)
        except KeyboardInterrupt:
            import sys
            sys.exit()

    def forward_call(self, calldata, procedure=1,  timeout=15.0, retries=3):
        while True:
            try:
                data = self.client.make_call(procedure, calldata)
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

    def handle_0(self, data, cred):
        """NULL procedure"""
        log.debug("*" * 20)
        log.debug("Handling NULL")
        try:
            self.forward_call(calldata="", procedure=0)
            return rpc.SUCCESS, ''
        except rpc.RPCTimeout:
            log.critical("Error: cannot connect to destination server")
            return rpc.GARBAGE_ARGS, None

    def handle_1(self, data, cred):
        """COMPOUND procedure"""
        log.debug("*" * 40)
        log.debug("Handling COMPOUND")
        # stage 1: data in XDR as received from the client
        unpacker = nfs4lib.FancyNFS4Unpacker(data)
        args = unpacker.unpack_COMPOUND4args()
        log.debug("Client sent:")
        log.debug(repr(args))
        unpacker.done()
        # stage 2: pre-processing - data in COMPOUND4args
        # XXX: check operation, alter stuff, delay etc. etc.
        for arg in args.argarray:
            opname = nfs_opnum4.get(arg.argop, 'op_illegal')
            log.info("*** %s (%d) ***" % (opname, arg.argop))
        #stage 3: repack the data and forward to server
        packer = nfs4lib.FancyNFS4Packer()
        packer.pack_COMPOUND4args(args)
        log.debug("Proxy sent:")
        log.debug(repr(args))
        calldata = packer.get_buffer()
        try:
            ret_data = self.forward_call(calldata)
        except rpc.RPCTimeout:
            log.critical("Error: cannot connect to destination server")
            return rpc.GARBAGE_ARGS, None
        # stage 4: data in XDR as returned by the server
        unpacker = nfs4lib.FancyNFS4Unpacker(ret_data)
        res = unpacker.unpack_COMPOUND4res()
        log.debug("Server returned:")
        log.debug(repr(res))
        unpacker.done()
        # stage 5: post-processing - data in COMPOUND4res
        # XXX: check operation etc.
        for arg in res.resarray:
            opname = nfs_opnum4.get(arg.resop, 'op_illegal')
            log.info("*** %s (%d) ***" % (opname, arg.resop))
        # state 6: repack and return XDR data to client
        packer = nfs4lib.FancyNFS4Packer()
        packer.pack_COMPOUND4res(res)
        log.debug("Proxy returned:")
        log.debug(repr(res))
        reply = packer.get_buffer()
        return rpc.SUCCESS, reply

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
    S = NFS4Proxy(port=opts.port, dserver=opts.dserver, dport=opts.dport)
    if True:
        S.start()
    else:
        import profile
        # This doesn't work well - only looks at main thread
        profile.run('S.start()', 'profile_data')
