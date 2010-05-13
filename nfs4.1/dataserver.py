import csv
import rpc
import nfs4lib
from nfs4_type import *
from nfs4_pack import NFS4Packer
from nfs4_const import *
import time
import logging
import nfs4client
import hashlib
import sys
import nfs4_ops as op

DS_PATH="pynfs_mds"

log = logging.getLogger("Dataserver Manager")

class DataServer(object):
    def __init__(self, server, port=2049, proto="tcp", flavor=rpc.AUTH_SYS, active=True, mdsds=True):
        self.mdsds = mdsds
        self.proto = proto
        self.server = server
        self.port = int(port)
        self.active = active
        self.path = [DS_PATH]
        self.filehandles = {}
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
        self.sess = c.create_session()
        self.make_root()

    def disconnect(self):
        self.sess.destroy()

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
        hex_port = hex(self.port)[2:].zfill(4)
        uaddr = '.'.join([self.server,
                          str(self.port >> 8),
                          str(self.port & 0xff)])
        return [netaddr4(self.proto, uaddr)]

    def make_root(self, attrs={FATTR4_MODE:0777}):
        kind = createtype4(NF4DIR)
        cr_ops = nfs4lib.use_obj(self.path[:-1]) + \
            [op.create(kind, self.path[-1], attrs)]
        self.execute(cr_ops, exceptions=[NFS4ERR_EXIST])
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
            res = self.execute(nfs4lib.use_obj(self.path) + [open_op, op.getfh()], exceptions=[NFS4ERR_EXIST])
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
        where each line has format e.g. 127.0.0.1:port
        """
        try:
            dsReader = csv.reader(open(filename), delimiter='\n')
            self.active = 1
        except IOError:
            log.error("Error reading file %s. \n --> pNFS-files export not activated" % filename)
            return None
        for conf in dsReader:
            # format ip:port
            try:
                dsopts = conf[0].partition(":")
                if not dsopts[2] or dsopts[2] == "":
                    ds = DataServer(dsopts[0], mdsds=self.mdsds)
                else:
                    ds = DataServer(server=dsopts[0], port=dsopts[2], mdsds=self.mdsds)
                    log.info("Adding dataserver ip:%s port:%s" % (ds.server, ds.port))
                self.list.append(ds)
            except IOError:
                log.critical("cannot connect to dataserver(s)")
                log.critical("check for blank lines in dataservers.conf")
                log.critical("or check dataserver status")
                sys.exit(1)
        self.address_body = self._get_address_body()
        return 0

    def _get_address_body(self):
        stripe_indices = []
        netaddrs = []
        index = 0
        for d in self.list:
            if d.active:
                netaddrs.append(d.get_netaddr4())
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
