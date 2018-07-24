import rpc.rpc as rpc
import nfs4lib
import xdrdef.nfs4_type as type4
from xdrdef.nfs4_pack import NFS4Packer
import xdrdef.nfs4_const as const4
import xdrdef.nfs3_type as type3
import xdrdef.nfs3_const as const3
import time
import logging
import nfs4client
import nfs3client
import hashlib
import sys
import nfs_ops
import socket

log = logging.getLogger("Dataserver Manager")

op4 = nfs_ops.NFS4ops()
op3 = nfs_ops.NFS3ops()

class DataServer(object):
    def __init__(self, server, port, path, flavor=rpc.AUTH_SYS, active=True, mdsds=True, multipath_servers=None, summary=None):
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

        self.summary = summary

        if active:
            self.up()

    def up(self):
        self.active = True
        if not self.mdsds:
            self.connect()
            self.make_root()

    def down(self):
        self.disconnect()
        self.active = False

    def reset(self):
        self.down()
        self.up()

    def get_netaddr4(self):
        # STUB server multipathing not supported yet
        uaddr = '.'.join([self.server,
                          str(self.port >> 8),
                          str(self.port & 0xff)])
        return type4.netaddr4(self.proto, uaddr)

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

            netaddr4s.append(type4.netaddr4(proto, uaddr))
        return netaddr4s

    def fh_to_name(self, mds_fh):
        return hashlib.sha1("%r" % mds_fh).hexdigest()

    def connect(self):
        raise NotImplemented

    def disconnect(self):
        pass

class DataServer41(DataServer):
    def _execute(self, ops, exceptions=[], delay=5, maxretries=3):
        """ execute the NFS call
        If an error code is specified in the exceptions it means that the
        caller wants to handle the error himself
        """
        retry_errors = [const4.NFS4ERR_DELAY, const4.NFS4ERR_GRACE]
        state_errors = [const4.NFS4ERR_STALE_CLIENTID, const4.NFS4ERR_BADSESSION,
                        const4.NFS4ERR_BADSLOT, const4.NFS4ERR_DEADSESSION]
        while True:
            res = self.sess.compound(ops)
            if res.status == const4.NFS4_OK or res.status in exceptions:
                return res
            elif res.status in retry_errors:
                if maxretries > 0:
                    maxretries -= 1
                    time.sleep(delay)
                else:
                    log.error("Too many retries with DS %s" % self.server)
                    raise Exception("Dataserver communication retry error")
            elif res.status in state_errors:
                self.reset()
            else:
                log.error("Unhandled status %s from DS %s" %
                          (nfsstat4[res.status], self.server))
                raise Exception("Dataserver communication error")

    def connect(self):
        # only support root with AUTH_SYS for now
        s1 = rpc.security.instance(rpc.AUTH_SYS)
        self.cred1 = s1.init_cred(uid=0, gid=0)
        self.c1 = nfs4client.NFS4Client(self.server, self.port,
                                        summary=self.summary)
        self.c1.set_cred(self.cred1)
        self.c1.null()
        c = self.c1.new_client("DS.init_%s" % self.server)
        # This is a hack to ensure MDS/DS communication path is at least
        # as wide as the client/MDS channel (at least for linux client)
        fore_attrs = type4.channel_attrs4(0, 16384, 16384, 2868, 8, 8, [])
        self.sess = c.create_session(fore_attrs=fore_attrs)
        self.sess.compound([op4.reclaim_complete(const4.FALSE)])

    def make_root(self):
        attrs = {const4.FATTR4_MODE:0o777}
        existing_path = []
        kind = type4.createtype4(const4.NF4DIR)
        for comp in self.path:
            existing_path.append(comp)
            res = self._execute(nfs4lib.use_obj(existing_path),
                               exceptions=[const4.NFS4ERR_NOENT])
            if res.status == const4.NFS4ERR_NOENT:
                cr_ops = nfs4lib.use_obj(existing_path[:-1]) + \
                    [op4.create(kind, comp, attrs)]
                self._execute(cr_ops)
        res = self._execute(nfs4lib.use_obj(self.path) + [op4.getfh()])
        self.path_fh = res.resarray[-1].object
        need = const4.ACCESS4_READ | const4.ACCESS4_LOOKUP | const4.ACCESS4_MODIFY | const4.ACCESS4_EXTEND
        res = self._execute(nfs4lib.use_obj(self.path_fh) + [op4.access(need)])
        if res.resarray[-1].access != need:
            raise RuntimeError
        # XXX clean DS directory

    def open_file(self, mds_fh):
        seqid=0
        access = const4.OPEN4_SHARE_ACCESS_BOTH
        deny = const4.OPEN4_SHARE_DENY_NONE
        attrs = {const4.FATTR4_MODE: 0o777}
        owner = "mds"
        mode = const4.GUARDED4
        verifier = self.sess.c.verifier
        openflag = type4.openflag4(const4.OPEN4_CREATE, type4.createhow4(mode, attrs, verifier))
        name = self.fh_to_name(mds_fh)
        while True:
            if mds_fh in self.filehandles:
                return
            open_op = op4.open(seqid, access, deny,
                              type4.open_owner4(self.sess.client.clientid, owner),
                              openflag, type4.open_claim4(const4.CLAIM_NULL, name))
            res = self._execute(nfs4lib.use_obj(self.path_fh) + [open_op, op4.getfh()], exceptions=[const4.NFS4ERR_EXIST])
            if res.status == const4.NFS4_OK:
                 ds_fh = res.resarray[-1].opgetfh.resok4.object
                 ds_openstateid = type4.stateid4(0, res.resarray[-2].stateid.other)
                 self.filehandles[mds_fh] = (ds_fh, ds_openstateid)
                 return
            elif res.status == const4.NFS4ERR_EXIST:
                 openflag = type4.openflag4(const4.OPEN4_NOCREATE)
            else:
                raise RuntimeError

    def close_file(self, mds_fh):
        """close the given file"""
        seqid=0 #FIXME: seqid must be !=0
        fh, stateid = self.filehandles[mds_fh]
        ops = [op4.putfh(fh)] + [op4.close(seqid, stateid)]
        res = self._execute(ops)
        # ignoring return
        del self.filehandles[mds_fh]

    def read(self, fh, pos, count):
        ops = [op4.putfh(fh),
               op4.read(nfs4lib.state00, pos, count)]
        # There are all sorts of error handling issues here
        res = self._execute(ops)
        data = res.resarray[-1].data
        return data

    def write(self, fh, pos, data):
        ops = [op4.putfh(fh),
               op4.write(nfs4lib.state00, pos, const4.FILE_SYNC4, data)]
        # There are all sorts of error handling issues here
        res = self._execute(ops)

    def truncate(self, fh, size):
        ops = [op4.putfh(fh),
               op4.setattr(nfs4lib.state00, {const4.FATTR4_SIZE: size})]
        res = self._execute(ops)

    def get_size(self, fh):
        ops = [op4.putfh(fh),
               op4.getattr(1 << const4.FATTR4_SIZE)]
        res = self._execute(ops)
        attrdict = res.resarray[-1].obj_attributes
        return attrdict.get(const4.FATTR4_SIZE, 0)

class DataServer3(DataServer):
    def _execute(self, procnum, procarg, exceptions=(), delay=5, maxretries=3):
        """ execute the NFS call
        If an error code is specified in the exceptions it means that the
        caller wants to handle the error himself
        """
        retry_errors = []
        while True:
            res = self.c1.proc(procnum, procarg)
            if res.status == const3.NFS3_OK or res.status in exceptions:
                return res
            elif res.status in retry_errors:
                if maxretries > 0:
                    maxretries -= 1
                    time.sleep(delay)
                else:
                    log.error("Too many retries with DS %s" % self.server)
                    raise Exception("Dataserver communication retry error")
            else:
                log.error("Unhandled status %s from DS %s" %
                          (const3.nfsstat3[res.status], self.server))
                raise Exception("Dataserver communication error")

    def connect(self):
        # only support root with AUTH_SYS for now
        s1 = rpc.security.instance(rpc.AUTH_SYS)
        self.cred1 = s1.init_cred(uid=0, gid=0)
        self.c1 = nfs3client.NFS3Client(self.server, self.port,
                                        summary=self.summary)
        self.c1.set_cred(self.cred1)
        self.rootfh = type3.nfs_fh3(self.c1.mntclnt.get_rootfh(self.path))
        self.c1.null()

    def make_root(self):
        """ don't actually make a root path - we must use it as the export """
        need = const3.ACCESS3_READ | const3.ACCESS3_LOOKUP | \
               const3.ACCESS3_MODIFY | const3.ACCESS3_EXTEND
        arg = op3.access(self.rootfh, need)
        res = self._execute(const3.NFSPROC3_ACCESS, arg)
        if res.resok.access != need:
            raise RuntimeError
        # XXX clean DS directory

    def open_file(self, mds_fh):
        name = self.fh_to_name(mds_fh)
        where = type3.diropargs3(self.rootfh, name)
        attr = type3.sattr3(mode=type3.set_mode3(True, 0o777),
                            uid=type3.set_uid3(True, 0),
                            gid=type3.set_gid3(True, 0),
                            size=type3.set_size3(False),
                            atime=type3.set_atime(False),
                            mtime=type3.set_mtime(False))
        how = type3.createhow3(const3.GUARDED, attr)
        arg = op3.create(where, how)
        res = self._execute(const3.NFSPROC3_CREATE, arg,
                            exceptions=(const3.NFS3ERR_EXIST,))

        if res.status == const3.NFS3_OK:
            self.filehandles[mds_fh] = (res.resok.obj.handle, None)

        else:
            arg = op3.lookup(type3.diropargs3(self.rootfh, name))
            res = self._execute(const3.NFSPROC3_LOOKUP, arg)

            self.filehandles[mds_fh] = (res.resok.object, None)

    def close_file(self, mds_fh):
        del self.filehandles[mds_fh]

    def read(self, fh, pos, count):
        arg = op3.read(fh, pos, count)
        res = self._execute(const3.NFSPROC3_READ, arg)
        # XXX check res.status?
        return res.resok.data

    def write(self, fh, pos, data):
        arg = op3.write(fh, pos, len(data), const3.FILE_SYNC, data)
        # There are all sorts of error handling issues here
        res = self._execute(const3.NFSPROC3_WRITE, arg)

    def truncate(self, fh, size):
        attr = type3.sattr3(mode=type3.set_mode3(False),
                            uid=type3.set_uid3(False),
                            gid=type3.set_gid3(False),
                            size=type3.set_size3(True, size),
                            atime=type3.set_atime(False),
                            mtime=type3.set_mtime(False))
        arg = op3.setattr(fh, attr, type3.sattrguard3(check=False))
        res = self._execute(const3.NFSPROC3_SETATTR, arg)

    def get_size(self, fh):
        arg = op3.getattr(fh)
        res = self._execute(const3.NFSPROC3_GETATTR, arg)
        # XXX check res.status?
        return res.resok.obj_attributes.size


class DSDevice(object):
    def __init__(self, mdsds):
        self.list = [] # list of DataServer41 instances
        # STUB only one data group supported for now
        self.devid = 0
        self.active = 0
        self.address_body = None # set by load()
        self.mdsds = mdsds # if you are both the DS and the MDS we are the only server

    def load(self, filename, server_obj):
        """ Read dataservers from configuration file:
        where each line has format e.g. server[:[port][/path]]
        """
        with open(filename) as fd:
            for line in fd:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                log.info("Analyzing: %r" % line)
                try:
                    server_list, path = nfs4lib.parse_nfs_url(line)
                except:
                    log.critical("Could not parse line: %r" % line)
                    sys.exit(1)

                # for now, just use the last path for local connections
                server, port = server_list[-1]
                server_list = server_list[:-1]
                try:
                    log.info("Adding dataserver ip:%s port:%s path:%s" %
                             (server, port, '/'.join(path)))
                    ds = DataServer41(server, port, path, mdsds=self.mdsds,
                                    multipath_servers=server_list,
                                    summary=server_obj.summary)
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
        addr = type4.nfsv4_1_file_layout_ds_addr4(stripe_indices, netaddrs)
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
