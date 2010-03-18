import csv
import rpc
import nfs4lib
from nfs4_type import netaddr4, nfsv4_1_file_layout_ds_addr4
from nfs4_pack import NFS4Packer
from nfs4_const import *
import logging
import nfs4client
import sys

log = logging.getLogger("Dataserver Manager")

class DataServer(object):
    def __init__(self, server, port=2049, proto="tcp", flavor=rpc.AUTH_SYS, active=True):
        self.proto = proto
        self.server = server
        self.port = int(port)
        self.active = active
        if active:
            self.up()

    def up(self):
        self.active = True
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

    def disconnect(self):
        self.sess.destroy()

    def get_netaddr4(self):
        # STUB server multipathing not supported yet
        hex_port = hex(self.port)[2:].zfill(4)
        uaddr = '.'.join([self.server,
                          str(self.port >> 8),
                          str(self.port & 0xff)])
        return [netaddr4(self.proto, uaddr)]

class DSDevice(object):
    def __init__(self):
        self.list = [] # list of DataServer instances
        # STUB only one data group supported for now
        self.devid = 0
        self.active = 0
        self.address_body = None # set by load()

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
                    ds = DataServer(dsopts[0])
                else:
                    ds = DataServer(server=dsopts[0], port=dsopts[2])
                    log.info("Adding dataserver ip:%s port:%s" % (ds.server, ds.port))
                self.list.append(ds)
            except:
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

