import rpc
import nfs4lib
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import NFS4Packer
from xdrdef.nfs4_const import *
import time
import logging
import nfs4client
import hashlib
import sys
import nfs4_ops as op
import socket

log = logging.getLogger("Dataserver Manager")

class DataServer(object):
    def __init__(self, server, port, path, flavor=rpc.AUTH_SYS, active=True, mdsds=True, multipath_servers=None):
        self.mdsds = mdsds
        self.server = server
        self.port = int(port)
        self.active = active
        self.path = path
        self.path_fh = None
        self.filehandles = {}

        self.proto = "tcp"
        if server.find(":") > -1:
            self.proto = "tcp6"

        if multipath_servers:
            self.multipath_servers = multipath_servers[:]
        else:
            self.multipath_servers = []

        if active:
            self.up()

    def up(self):
        self.active = True
        if not self.mdsds:
            self.connect()

    def down(self):
        self.active = False

    def connect(self):
        # only support root with AUTH_SYS for now
        s1 = rpc.security.instance(rpc.AUTH_SYS)
        self.cred1 = s1.init_cred(uid=0, gid=0)
        self.c1 = nfs4client.NFS4Client(self.server, self.port)
        self.c1.set_cred(self.cred1)
        self.c1.null()
        c = self.c1.new_client("DS.init_%s" % self.server)
        # This is a hack to ensure MDS/DS communication path is at least
        # as wide as the client/MDS channel (at least for linux client)
        fore_attrs = channel_attrs4(0, 16384, 16384, 2868, 8, 8, [])
        self.sess = c.create_session(fore_attrs=fore_attrs)
        sess.compound([op.reclaim_complete(FALSE)])
        self.make_root()

    def disconnect(self):
        pass

    def execute(self, ops, exceptions=[], delay=5, maxretries=3):
        """ execute the NFS call
        If an error code is specified in the exceptions it means that the
        caller wants to handle the error himself
        """
        retry_errors = [NFS4ERR_DELAY, NFS4ERR_GRACE]
        state_errors = [NFS4ERR_STALE_CLIENTID, NFS4ERR_BADSESSION,
                        NFS4ERR_BADSLOT, NFS4ERR_DEADSESSION]
        while True:
            res = self.sess.compound(ops)
            if res.status == NFS4_OK or res.status in exceptions:
                return res
            elif res.status in retry_errors:
                if maxretries > 0:
                    maxretries -= 1
                    time.sleep(delay)
                else:
                    log.error("Too many retries with DS %s" % self.server)
                    raise Exception("Dataserver communication retry error")
            elif res.status in state_errors:
                self.disconnect()
                self.connect()
            else:
                log.error("Unhandled status %s from DS %s" %
                          (nfsstat4[res.status], self.server))
                raise Exception("Dataserver communication error")

    def get_netaddr4(self):
        # STUB server multipathing not supported yet
        uaddr = '.'.join([self.server,
                          str(self.port >> 8),
                          str(self.port & 0xff)])
        return netaddr4(self.proto, uaddr)

    def get_multipath_netaddr4s(self):
        netaddr4s = []
        for addr in self.multipath_servers:
            server, port = addr
            uaddr = '.'.join([server,
                            str(port >> 8),
                            str(port & 0xff)])
            proto = "tcp"
            if server.find(':') >= 0:
                proto = "tcp6"

            netaddr4s.append(netaddr4(proto, uaddr))
        return netaddr4s


    def make_root(self, attrs={FATTR4_MODE:0777}):
        existing_path = []
        kind = createtype4(NF4DIR)
        for comp in self.path:
            existing_path.append(comp)
            res = self.execute(nfs4lib.use_obj(existing_path),
                               exceptions=[NFS4ERR_NOENT])
            if res.status == NFS4ERR_NOENT:
                cr_ops = nfs4lib.use_obj(existing_path[:-1]) + \
                    [op.create(kind, comp, attrs)]
                self.execute(cr_ops)
        res = self.execute(nfs4lib.use_obj(self.path) + [op.getfh()])
        self.path_fh = res.resarray[-1].object
        need = ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND
        res = self.execute(nfs4lib.use_obj(self.path_fh) + [op.access(need)])
        if res.resarray[-1].access != need:
            raise RuntimeError
        # XXX clean DS directory

    def fh_to_name(self, mds_fh):
        return hashlib.sha1("%r" % mds_fh).hexdigest()

    def open_file(self, mds_fh, seqid=0,
                  access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE,
                  attrs={FATTR4_MODE: 0777}, owner = "mds", mode=GUARDED4):
        verifier = self.sess.c.verifier
        openflag = openflag4(OPEN4_CREATE, createhow4(mode, attrs, verifier))
        name = self.fh_to_name(mds_fh)
        while True:
            if mds_fh in self.filehandles:
                return
            open_op = op.open(seqid, access, deny,
                              open_owner4(self.sess.client.clientid, owner),
                              openflag, open_claim4(CLAIM_NULL, name))
            res = self.execute(nfs4lib.use_obj(self.path_fh) + [open_op, op.getfh()], exceptions=[NFS4ERR_EXIST])
            if res.status == NFS4_OK:
                 ds_fh = res.resarray[-1].opgetfh.resok4.object
                 ds_openstateid = stateid4(0, res.resarray[-2].stateid.other)
                 self.filehandles[mds_fh] = (ds_fh, ds_openstateid)
                 return
            elif res.status == NFS4ERR_EXIST:
                 openflag = openflag4(OPEN4_NOCREATE)
            else:
                raise RuntimeError

    def close_file(self, mds_fh):
        """close the given file"""
        seqid=0 #FIXME: seqid must be !=0
        fh, stateid = self.filehandles[mds_fh]
        ops = [op.putfh(fh)] + [op.close(seqid, stateid)]
        res = self.execute(ops)
        # ignoring return
        del self.filehandles[mds_fh]

class DSDevice(object):
    def __init__(self, mdsds):
        self.list = [] # list of DataServer instances
        # STUB only one data group supported for now
        self.devid = 0
        self.active = 0
        self.address_body = None # set by load()
        self.mdsds = mdsds # if you are both the DS and the MDS we are the only server

    def load(self, filename):
        """ Read dataservers from configuration file:
        where each line has format e.g. server[:[port][/path]]
        """
        with open(filename) as fd:
            for line in fd:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                print "Analyzing: %r" % line
                try:
                    server_list, path = nfs4lib.parse_nfs_url(line)
                except:
                    log.critical("Could not parse line: %r" % line)
                    sys.exit(1)

                # for now, just use the last path for local connections
                server, port = server_list[-1]
                server_list = server_list[:-1]
                print server, port, path
                try:
                    log.info("Adding dataserver ip:%s port:%s path:%s" %
                             (server, port, '/'.join(path)))
                    ds = DataServer(server, port, path, mdsds=self.mdsds,
                                    multipath_servers=server_list)
                    self.list.append(ds)
                except socket.error:
                    log.critical("cannot access %s:%i/%s" %
                                 (server, port, '/'.join(path)))
                    sys.exit(1)
        self.active = 1
        self.address_body = self._get_address_body()

    def _get_address_body(self):
        stripe_indices = []
        netaddrs = []
        index = 0
        for d in self.list:
            if d.active:
                multipath = []
                multipath.extend(d.get_multipath_netaddr4s())
                multipath.append(d.get_netaddr4())
                netaddrs.append(multipath)
                stripe_indices.append(index)
                index = index + 1
        addr = nfsv4_1_file_layout_ds_addr4(stripe_indices, netaddrs)
        p = NFS4Packer()
        p.pack_nfsv4_1_file_layout_ds_addr4(addr)
        return p.get_buffer()

    def open_ds_file(self, mds_fh):
        if self.mdsds:
            return
        for d in self.list:
            if d.active:
                d.open_file(mds_fh)

    def close_ds_file(self, mds_fh):
        if self.mdsds:
            return
        for d in self.list:
            if d.active:
                d.close_file(mds_fh)

    def get_ds_filehandles(self, mds_fh):
        if self.mdsds:
            return [mds_fh]
        else:
            # XXX handle exceptions
            return [d.filehandles[mds_fh][0] for d in self.list if d.active]
