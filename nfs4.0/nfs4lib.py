#!/usr/bin/env python3
# nfs4lib.py - NFS4 library for Python
#
# Requires python 3.2
#
# Written by Fred Isaman <iisaman@citi.umich.edu>
# Copyright (C) 2004 University of Michigan, Center for
#                    Information Technology Integration
#
# Based on version
# Written by Peter Astrand <peter@cendio.se>
# Copyright (C) 2001 Cendio Systems AB (http://www.cendio.se)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

from __future__ import absolute_import

import time
import struct
import socket
import sys
import re
import inspect
from os.path import basename
import threading

import rpc.rpc as rpc
import rpc.rpc_const as rpc_const
import xdrdef.nfs4_const as nfs4_const
from  xdrdef.nfs4_const import *
import xdrdef.nfs4_type as nfs4_type
from xdrdef.nfs4_type import *
from xdrlib import Error as XDRError
import xdrdef.nfs4_pack as nfs4_pack

import nfs_ops
op4 = nfs_ops.NFS4ops()

class NFSException(rpc.RPCError):
    pass

class BadCompoundRes(NFSException):
    """The COMPOUND procedure returned some kind of error, ie is not NFS4_OK"""
    def __init__(self, operation, errcode, msg=None):
        self.operation = operation
        self.errcode = errcode
        if msg:
            self.msg = msg + ': '
        else:
            self.msg = ''
    def __str__(self):
        if self.operation is None:
            return self.msg + "empty compound return with status %s" % \
                   nfsstat4[self.errcode]
        else:
            return self.msg + \
                   "operation %s should return NFS4_OK, instead got %s" % \
                   (nfs_opnum4[self.operation], nfsstat4[self.errcode])

class UnexpectedCompoundRes(NFSException):
    """The COMPOUND procedure returned OK, but had unexpected data"""
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        if self.msg:
            return "Unexpected COMPOUND result: %s" % self.msg
        else:
            return "Unexpected COMPOUND result"

class InvalidCompoundRes(NFSException):
    """The COMPOUND return is invalid, ie response is not to spec"""
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        if self.msg:
            return "Invalid COMPOUND result: %s" % self.msg
        else:
            return "Invalid COMPOUND result"

class FancyNFS4Packer(nfs4_pack.NFS4Packer):
    """Handle fattr4 and dirlist4 more cleanly than auto-generated methods"""
    def filter_bitmap4(self, data):
        out = []
        while data:
            out.append(data & 0xffffffff)
            data >>= 32
        return out

    def filter_fattr4(self, data):
        """Allow direct encoding of dict, instead of opaque attrlist"""
        if type(data) is dict:
            data = dict2fattr(data)
        return data

    # def pack_dirlist4(self):

class FancyNFS4Unpacker(nfs4_pack.NFS4Unpacker):
    def filter_bitmap4(self, data):
        """Put bitmap into single long, instead of array of 32bit chunks"""
        out = 0
        shift = 0
        for i in data:
            out |= (int(i) << shift)
            shift += 32
        return out

    def filter_fattr4(self, data):
        """Return as dict, instead of opaque attrlist"""
        return fattr2dict(data)


    def filter_dirlist4(self, data):
        """Return as simple list, instead of strange chain structure"""
        e = data.entries
        if not e:
            return data
        array = [e[0]]
        while e[0].nextentry:
            e = e[0].nextentry
            array.append(e[0])
        data.entries = array
        return data


# STUB
class CBServer(rpc.RPCServer):
    def __init__(self, client):
        # Add 12345 to reveal servers that hardcode their program number
        self.prog = 0x40000000 + 12345 # Use transient
        self.port = 0
        self.client = client
        rpc.RPCServer.__init__(self, prog=self.prog, vers=1, port=self.port)
        packed = struct.pack('>H', self.port)
        try:     #for python2
            self.dotport = b'.%s.%s' % (ord(packed[0]), ord(packed[1]))
        except:  #for python3
            self.dotport = b'.%d.%d' % ((packed[0]), (packed[1]))
        self.nfs4packer = FancyNFS4Packer()
        self.nfs4unpacker = FancyNFS4Unpacker('')
        self.recall_lock = threading.Lock()
        self.recall_lock.acquire()
        self.recall_funct = {}
        self.recall_return = {}
        self.recall_res = {}
        self.recall_lock.release()
        self.opcodes = {
            OP_CB_GETATTR: self.O_CB_GetAttr,
            OP_CB_RECALL: self.O_CB_Recall,
            #OP_CB_ILLEGAL: self.O_CB_Illegal,
            }
        self.opcounts = {
            OP_CB_GETATTR: 0,
            OP_CB_RECALL: 0,
            #OP_CB_ILLEGAL: 0,
            }

    def set_cb_recall(self, cbid, funct, ret):
        self.recall_lock.acquire()
        self.recall_funct[cbid] = funct
        self.recall_return[cbid] = ret
        self.recall_lock.release()

    def clear_cb_recall(self, cbid):
        self.recall_lock.acquire()
        del self.recall_funct[cbid]
        del self.recall_return[cbid]
        self.recall_lock.release()

    def get_recall_res(self, cbid):
        self.recall_lock.acquire()
        res = self.recall_res.get(cbid, None)
        self.recall_lock.release()
        return res

    def simple_status(self, status, *args):
        """Called from function O_<Name>, sets up a simple status response"""
        # Get name of calling function
        name = sys._getframe(1).f_code.co_name
        # Encode response
        if name.startswith("O_CB_"):
            name = name[2:]
            res = getattr(nfs4_type, name.upper() + "4res")(status, *args)
            argop4 = nfs_cb_resop4(getattr(nfs4_const,
                                           "OP_" + name.upper()))
            setattr(argop4, "opcb" + name[3:].lower(), res)
            return (status, argop4)
        else:
            raise "Bad name %s" % name

    def run(self):
        rpc.RPCServer.run(self)

    def handle_0(self, data, cred):
        #print("*****CB received NULL******")
        if data != b'':
            return rpc.GARBAGE_ARGS, b''
        else:
            return rpc.SUCCESS, b''

    def handle_1(self, data, cred):
        """Deal with CB_COMPOUND"""
        print("*****CB received COMPOUND******")
        self.nfs4unpacker.reset(data)
        ok, results, tag = self.O_CB_Compound()
        try:
            self.nfs4unpacker.done()
        except XDRError:
            return rpc.GARBAGE_ARGS, b''
        cmp4res = CB_COMPOUND4res(ok, tag, results)
        self.nfs4packer.reset()
        self.nfs4packer.pack_CB_COMPOUND4res(cmp4res)
        return rpc.SUCCESS, self.nfs4packer.get_buffer()

    def O_CB_Compound(self):
        tag = b''
        try:
            cmp4args = self.nfs4unpacker.unpack_CB_COMPOUND4args()
            tag = cmp4args.tag
            cbid = cmp4args.callback_ident
        except XDRError:
            return NFS4ERR_BADXDR, [], tag
        if cmp4args.minorversion != 0:
            return NFS4ERR_MINOR_VERS_MISMATCH, [], tag
        results = []
        ok = NFS4_OK
        for op in cmp4args.argarray:
            if op.argop in self.opcodes:
                ok, result = self.opcodes[op.argop](op, cbid)
            else:
                ok = NFS4ERR_OP_ILLEGAL
                resop4 = CB_ILLEGAL4res(NFS4ERR_OP_ILLEGAL)
                result = nfs_cb_resop4(resop=OP_ILLEGAL, opcbillegal=resop4)
            results += [ result ]
            if ok != NFS4_OK:
                break
        return ok, results, tag

    # FIXME
    def O_CB_GetAttr(self, op, cbid):
        print("******* CB_Getattr *******")
        self.opcounts[OP_CB_GETATTR] += 1
        if not self.curr_fh:
            return self.simple_status(NFS4ERR_NOFILEHANDLE)
        garesok = GETATTR4resok({})
        return self.simple_status(NFS4_OK, garesok)

    # FIXME
    def O_CB_Recall(self, op, cbid):
        print("******* CB_Recall (id=%i)********" % cbid)
        self.opcounts[OP_CB_RECALL] += 1
        if self.recall_funct.get(cbid, None) is not None:
            res = self.recall_funct[cbid](self.client, op, cbid)
            self.recall_lock.acquire()
            self.recall_res[cbid] = res
            self.recall_funct[cbid] = None
            self.recall_lock.release()
        res = self.simple_status(self.recall_return.get(cbid, NFS4_OK))
        self.recall_lock.acquire()
        self.recall_return[cbid] = NFS4_OK
        self.recall_lock.release()
        return res

# STUB
AuthSys = rpc.SecAuthSys(0,b'jupiter',103558,100,[])

class NFS4Client(rpc.RPCClient):
    def __init__(self, id, host=b'localhost', port=2049, homedir=[b'pynfs'],
                 sec_list=[AuthSys], opts=None):
        self._start_cb_server("cb_server_%s" % id)
        self.nfs4packer = FancyNFS4Packer()
        self.nfs4unpacker = FancyNFS4Unpacker('')
        self.homedir = homedir
        self.verifier = struct.pack('>d', time.time())
        self.id = id
        self.cbid = 0
        self.seqid = {}
        self.opts = opts
        uselowport = getattr(opts, "secure", False)
        rpc.RPCClient.__init__(self, host, port,
                               program=NFS4_PROGRAM, version=4,
                               sec_list=sec_list, uselowport=uselowport)

    def _start_cb_server(self, name=None):
        # Start up callback server associated with this client
        self.cb_server = CBServer(self)
        self.thread = threading.Thread(target=self.cb_server.run, name=name)
        self.thread.setDaemon(True)
        self.thread.start()
        # Establish callback control socket
        self.cb_control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while 1:
            try:
                self.cb_control.connect(('127.0.0.1', self.cb_server.port))
                break
            except socket.error:
                print("Waiting for Callback server to start")

    def cb_command(self, comm):
        self.cb_control.sendall(b'\x80\x00\x00\x04\x00\x00\x00%s' %
                                                            bytes([comm]))
        res = self.cb_control.recv(1024)

    def null(self):
        """Make NULL procedure call"""
        res = self.call(NFSPROC4_NULL, b'')
        self.nfs4unpacker.reset(res)
        self.nfs4unpacker.done()

    def compound(self, argarray, tag=b'', minorversion=0):
        """Make COMPOUND procedure call"""
        if type(argarray) is not list:
            raise "Need list for argarray"

        if len(tag) == 0:
            compound_tag = self.create_tag()
        else:
            compound_tag = tag
        # Make the actual call
        compoundargs = COMPOUND4args(argarray=argarray, tag=compound_tag,
                                     minorversion=minorversion)
        if SHOW_TRAFFIC:
            print
            print(compoundargs)
        p = self.nfs4packer
        un_p = self.nfs4unpacker
        p.reset()
        p.pack_COMPOUND4args(compoundargs)
        res = self.call(NFSPROC4_COMPOUND, p.get_buffer())
        un_p.reset(res)
        res = un_p.unpack_COMPOUND4res()
        if SHOW_TRAFFIC:
            print(res)
        un_p.done()

        # Do some error checking

        # If res.status==NFS4_OK, send_ops should equal recv_ops.
        # Otherwise, the recv_ops should equal the head of the send_ops list.
        # An exception to the above is if an illegal op was sent, in
        # which case it should be changed to OP_ILLEGAL in recv_ops.
        sent_ops = [op.argop for op in argarray]
        sent_ops = list(map(lambda x: (x in nfs_opnum4) and x or OP_ILLEGAL,
                       sent_ops))
        recv_ops = [op.resop for op in res.resarray]
        if res.status == NFS4_OK and len(recv_ops) < len(sent_ops):
            raise InvalidCompoundRes("Truncated response list.")
        if sent_ops[:len(recv_ops)] != recv_ops:
            raise InvalidCompoundRes("Returned ops = %s, expected %s" %
                             (str(recv_ops), str(sent_ops[:len(recv_ops)])) )

        if res.status == NFS4_OK:
            # All operations status should also be NFS4_OK
            # Note: A zero-length res.resarray is possible
            for resop in res.resarray:
                if resop.switch.status != NFS4_OK:
                    raise InvalidCompoundRes("res.status was OK, but some"
                                             "operations returned errors")
        else:
            # Note: A zero-length res.resarray is possible
            if res.resarray:
                # All operations up to the last should return NFS4_OK
                for resop in res.resarray[:-1]:
                    if resop.switch.status != NFS4_OK:
                        raise InvalidCompoundRes("non-last operations returned error")
                # The last operation result must be equal to res.status
                lastop = res.resarray[-1]
                if lastop.switch.status != res.status:
                    raise InvalidCompoundRes("last op not equal to res.status")

        return res

    def create_tag(self):
        current_module = inspect.getmodule(inspect.currentframe().f_back)
        current_stack = inspect.stack()
        stackid = 0
        while current_module == inspect.getmodule(current_stack[stackid][0]):
              stackid = stackid + 1
        test_name = '%s:%s' % (basename(current_stack[stackid][1]), current_stack[stackid][3])
        return test_name.encode('utf8')

    def init_connection(self, id=None, verifier=None, cb_ident=None):
        """Do setclientid/setclientidconfirm combination"""
        # SETCLIENTID
        res = self.compound([self.setclientid(id, verifier, cb_ident)])
        check_result(res)
        self.clientid = res.resarray[0].switch.switch.clientid
        confirm = res.resarray[0].switch.switch.setclientid_confirm
        # SETCLIENTID_CONFIRM
        confirmop = op4.setclientid_confirm(self.clientid, confirm)
        res = self.compound([confirmop])
        try: check_result(res)
        except BadCompoundRes:
            if res.status not in [NFS4ERR_RESOURCE, NFS4ERR_DELAY]: raise
            # FIXME retry (ibm workaround)
            res = self.compound([confirmop])
            check_result(res)
        return self.clientid, confirm

    def setclientid(self, id=None, verifier=None, cb_ident=None):
        # cb_ident==None means turn off callbacks
        # cb_ident==0 means assign next available cb_ident
        # otherwise use given cb_ident
        if id is None: id = self.id
        if verifier is None: verifier = self.verifier
        if cb_ident is None:
            # Don't use callbacks
            r_addr = b"0.0.0.0.0.0"
            cb_ident = 0
        else:
            if cb_ident == 0:
                cb_ident = self.get_cbid()
            r_addr = self.ipaddress + self.cb_server.dotport
        client_id = nfs_client_id4(verifier, id)
        cb_location = clientaddr4(b'tcp', r_addr)
        callback = cb_client4(self.cb_server.prog, cb_location)

        return op4.setclientid(client_id, callback, cb_ident)

    def get_cbid(self):
        self.cbid += 1
        return self.cbid

    def get_seqid(self, owner):
        if owner not in self.seqid:
            self.seqid[owner] = 0
            return 0
        else:
            return self.seqid[owner]

    def advance_seqid(self, owner, res):
        no_adv = [ NFS4ERR_STALE_CLIENTID, NFS4ERR_STALE_STATEID,
                   NFS4ERR_BAD_STATEID, NFS4ERR_BAD_SEQID, NFS4ERR_BADXDR,
                   NFS4ERR_RESOURCE, NFS4ERR_NOFILEHANDLE]
        if res.status not in no_adv and owner in self.seqid:
            self.seqid[owner] += 1
            if self.seqid[owner] >= 0x100000000:
                self.seqid[owner] = 0

    def getattr(self, attrlist=[]):
        # The argument to GETATTR4args is a list of integers.
        return op4.getattr(list2bitmap(attrlist))

    def readdir(self, cookie=0, cookieverf=b'', dircount=0, maxcount=4096,
                attr_request=[]):
        attrs = list2bitmap(attr_request)
        return op4.readdir(cookie, cookieverf, dircount, maxcount, attrs)

    def read(self, offset=0, count=2048, stateid=stateid4(0, b'')):
        return op4.read(stateid, offset, count)

    def setattr(self, attrdict, stateid=None):
        if stateid is None: stateid = stateid4(0, b"")
        return op4.setattr(stateid, attrdict)

    def link(self, old, new):
        ops = self.use_obj(old) + [op4.savefh()]
        ops += self.use_obj(new[:-1])
        ops += [op4.link(new[-1])]
        return self.compound(ops)

    def open(self, owner, name=None, type=OPEN4_NOCREATE,
             mode=UNCHECKED4, attrs={FATTR4_MODE:0o644}, verf=None,
             access=OPEN4_SHARE_ACCESS_READ,
             deny=OPEN4_SHARE_DENY_WRITE,
             claim_type=CLAIM_NULL, deleg_type=None, deleg_cur_info=None):
        if name is None:
            name = owner
        seqid = self.get_seqid(owner)
        openowner = open_owner4(self.clientid, owner)
        if type == OPEN4_NOCREATE:
            openhow = openflag4(type)
        elif type == OPEN4_CREATE:
            openhow = openflag4(type, createhow4(mode, attrs, verf))
        claim = open_claim4(claim_type, name, deleg_type, deleg_cur_info)
        return op4.open(seqid, access, deny, openowner, openhow, claim)

    def lookup_path(self, dir):
        return [op4.lookup(comp) for comp in dir]

    def lookupp_path(self, dir):
    	return [op4.lookupp() for comp in dir]

    def go_home(self):
        """Return LOOKUP ops to get to homedir"""
        return [op4.putrootfh()] + self.lookup_path(self.homedir)

    def use_obj(self, file):
        """File is either None, a fh, or a list of path components"""
        if file is None or file == [None]:
            return []
        elif type(file) is bytes:
            return [op4.putfh(file)]
        else:
            return [op4.putrootfh()] + self.lookup_path(file)

    def do_getattrdict(self, file, attrlist):
        """file can be either a fh or a path"""
        ops = self.use_obj(file)
        ops += [self.getattr(attrlist)]
        res = self.compound(ops)
        check_result(res)
        return res.resarray[-1].obj_attributes


    def do_getattr(self, attr, file=None):
        if file is None: file = c.homedir
        d = self.do_getattrdict(file, [attr])
        if attr in d:
            return d[attr]
        else:
            return None

    def do_getfh(self, path):
        """Get filehandle"""
        ops = [op4.putrootfh()] + self.lookup_path(path)
        ops += [op4.getfh()]
        res = self.compound(ops)
        check_result(res)
        return res.resarray[-1].switch.switch.object

    def do_readdir(self, file, cookie=0, cookieverf = b'', attr_request=[],
                   dircount=4096, maxcount=4096):
        # Since we may not get whole directory listing in one readdir request,
        # loop until we do. For each request result, create a flat list
        # with <entry4> objects.
        attrs = list2bitmap(attr_request)
        cookie = 0
        cookieverf = b''
        entries = []
        baseops = self.use_obj(file)
        count = 0
        while 1:
            count += 1
            readdirop = op4.readdir(cookie, cookieverf,
                                        dircount, maxcount, attrs)
            res = self.compound(baseops + [readdirop])
            check_result(res, "READDIR with cookie=%i, maxcount=%i" %
                         (cookie, maxcount))
            reply = res.resarray[-1].switch.switch.reply
            if not reply.entries:
                if not reply.eof:
                    raise UnexpectedCompoundRes("READDIR had no entries")
                else:
                    break
            entry = reply.entries[0]
            # Loop over all entries in result.
            while 1:
                entry.attrdict = entry.attrs
                entry.count = count
                entries.append(entry)
                if not entry.nextentry:
                    break
                entry = entry.nextentry[0]
            if reply.eof:
                break
            cookie = entry.cookie
            cookieverf = res.resarray[-1].switch.switch.cookieverf
        return entries

    def clean_dir(self, path):
        stateid = stateid4(0, b"")
        fh = self.do_getfh(path)
        entries = self.do_readdir(fh)
        for e in entries:
            # We separate setattr and remove to avoid an inode locking bug
            ops = [op4.putfh(fh), op4.lookup(e.name)]
            ops += [op4.setattr(stateid, {FATTR4_MODE:0o755})]
            res = self.compound(ops)
            check_result(res, "Making sure %s is writable" % repr(e.name))
            ops = [op4.putfh(fh), op4.remove(e.name)]
            res = self.compound(ops)
            if res.status == NFS4ERR_NOTEMPTY:
                self.clean_dir(path + [e.name])
                res = self.compound(ops)
            check_result(res, "Trying to remove %s" % repr(e.name))

    def supportedAttrs(self, path=None):
        """Returns bitmask of supported attributes"""
        if not path: path = self.homedir
        d = self.do_getattrdict(path, [FATTR4_SUPPORTED_ATTRS])
        return d[FATTR4_SUPPORTED_ATTRS]

    def getLeaseTime(self):
        """Get length of lease time in seconds"""
        d = self.do_getattrdict([], [FATTR4_LEASE_TIME])
        return d[FATTR4_LEASE_TIME]

    def create_obj(self, path, type=NF4DIR, attrs={FATTR4_MODE:0o755},
                   linkdata=b"/etc/X11"):
        if __builtins__['type'](path) is bytes:
            path = self.homedir + [path]
        ops = [op4.putrootfh()] + self.lookup_path(path[:-1])
        if type in [NF4DIR, NF4SOCK, NF4FIFO, NF4REG]:
            objtype = createtype4(type)
        elif type == NF4LNK:
            objtype = createtype4(NF4LNK, linkdata)
        elif type in [NF4BLK, NF4CHR]:
            devdata = specdata4(1, 2)
            objtype = createtype4(type, devdata=devdata)
        ops += [op4.create(objtype, path[-1], attrs)]
        return self.compound(ops)

    def rename_obj(self, oldpath, newpath):
        # Set (sfh) to olddir
        ops = self.use_obj(oldpath[:-1]) + [op4.savefh()]
        # Set (cfh) to newdir
        ops += self.use_obj(newpath[:-1])
        # Call rename
        ops += [op4.rename(oldpath[-1], newpath[-1])]
        return self.compound(ops)

    def create_file(self, owner, path=None, attrs={FATTR4_MODE: 0o644},
                    access=OPEN4_SHARE_ACCESS_BOTH,
                    deny=OPEN4_SHARE_DENY_WRITE,
                    mode=UNCHECKED4, verifier=None,
                    set_recall=0, recall_funct=None, recall_return=NFS4_OK):
        # Set defaults
        if path is None:
            dir = self.homedir
            name = owner
        else:
            dir = path[:-1]
            name = path[-1]
        if (mode==EXCLUSIVE4) and (verifier==None):
            verifier = 'verifier'
        if set_recall:
            self.cb_server.set_cb_recall(self.cbid,
                                         recall_funct, recall_return)
        # Create the file
        ops = self.use_obj(dir)
        ops += [self.open(owner, name, OPEN4_CREATE, mode, attrs, verifier,
                          access, deny)]
        ops += [op4.getfh()]
        res = self.compound(ops)
        self.advance_seqid(owner, res)
        if set_recall and (res.status != NFS4_OK or \
           res.resarray[-2].switch.switch.delegation == OPEN_DELEGATE_NONE):
            # There was no delegation granted, so clean up recall info
            self.cb_server.clear_cb_recall(self.cbid)
        return res

    def open_file(self, owner, path=None,
                  access=OPEN4_SHARE_ACCESS_READ,
                  deny=OPEN4_SHARE_DENY_WRITE,
                  claim_type=CLAIM_NULL, deleg_type=None, deleg_stateid=None,
                  set_recall=False, recall_funct=None, recall_return=NFS4_OK):
        # Set defaults
        if path is None:
            dir = self.homedir
            name = owner
        else:
            dir = path[:-1]
            name = path[-1]
        # Open the file
        deleg_cur_info = None
        if claim_type==CLAIM_NULL:
            ops = self.use_obj(dir)
            if set_recall:
                self.cb_server.set_cb_recall(self.cbid,
                                             recall_funct, recall_return)
        elif claim_type==CLAIM_PREVIOUS:
            ops = [op4.putfh(path)]
        elif claim_type==CLAIM_DELEGATE_CUR:
            ops = self.use_obj(dir)
            deleg_cur_info = open_claim_delegate_cur4(deleg_stateid, name)
        ops += [self.open(owner, name, access=access, deny=deny,
                          claim_type=claim_type, deleg_type=deleg_type,
                          deleg_cur_info=deleg_cur_info)]
        ops += [op4.getfh()]
        res = self.compound(ops)
        self.advance_seqid(owner, res)
        if set_recall and (res.status != NFS4_OK or \
           res.resarray[-2].switch.switch.delegation == OPEN_DELEGATE_NONE):
            # There was no delegation granted, so clean up recall info
            self.cb_server.clear_cb_recall(self.cbid)
        return res

    def confirm(self, owner, res):
        """Takes res from an self.create_file and does open_confirm"""
        check_result(res)
        # FRED - how handle this check?
        #attrlist = bitmap2list(res.resarray[-2].switch.switch.attrset)
        #attrlist.sort()
        #expect = attrs.keys()
        #expect.sort()
        #if attrlist != expect:
        #    print("WARNING: OPENresok.attrset mismatches requested attrs")
        fhandle = res.resarray[-1].switch.switch.object
        stateid = res.resarray[-2].switch.switch.stateid
        rflags = res.resarray[-2].switch.switch.rflags
        if rflags & OPEN4_RESULT_CONFIRM:
            ops = [op4.putfh(fhandle)]
            ops += [op4.open_confirm(stateid, self.get_seqid(owner))]
            res = self.compound(ops)
            self.advance_seqid(owner, res)
            check_result(res)
            stateid = res.resarray[-1].switch.switch.open_stateid
        return (fhandle, stateid)


    def create_confirm(self, owner, path=None, attrs={FATTR4_MODE: 0o644},
                       access=OPEN4_SHARE_ACCESS_BOTH,
                       deny=OPEN4_SHARE_DENY_WRITE,
                       mode=GUARDED4):
        """Create (using open) a regular file, and confirm the open

        Returns the fhandle and stateid from the confirm.
        """
        res = self.create_file(owner, path, attrs, access, deny, mode)
        check_result(res, "Creating file %s" % _getname(owner, path))
        return self.confirm(owner, res)

    def open_confirm(self, owner, path=None,
                     access=OPEN4_SHARE_ACCESS_READ,
                     deny=OPEN4_SHARE_DENY_WRITE):
        while 1:
            res = self.open_file(owner, path, access, deny)
            cnt = 0
            try:
                 check_result(res, "Opening file %s" % _getname(owner, path))
                 break
            except BadCompoundRes:
                if res.status != NFS4ERR_DELAY: raise
                cnt += 1
                if cnt <= 5:
                    time.sleep(2)
                else:
                    raise UnexpectedCompoundRes("OPEN timed out on NFS4ERR_DELAY")
        return self.confirm(owner, res)

##     def xxxopen_claim_prev(self, owner, fh, seqid=None,
##                        check=None, error=NFS4_OK, msg=''):
##         # Set defaults
##         access=OPEN4_SHARE_ACCESS_READ
##         deny=OPEN4_SHARE_DENY_WRITE
##         if seqid is None:
##             seqid = self.get_seqid(owner)
##         if check is None:
##             check = lambda x,y,z: True

##         if fh is None:
##             ops = []
##         else:
##             ops = [op4.putfh(fh)]
##         claim = open_claim4(CLAIM_PREVIOUS,
##                             delegate_type=OPEN_DELEGATE_NONE)
##         openowner = open_owner4(self.clientid, owner)
##         how = openflag4(OPEN4_NOCREATE)
##         ops += [op4.open(seqid, access, deny, openowner, how, claim)]
##         ops += [op4.getfh()]
##         res = self.compound(ops)
##         self.advance_seqid(owner, res)
##         check(res, error, msg)
##         if res.status != NFS4_OK:
##             return (None, None)
##         fhandle = res.resarray[-1].switch.switch.object
##         stateid = res.resarray[-2].switch.switch.stateid
##         return (fhandle, stateid)

    def downgrade_file(self, owner, file, stateid,
                       access=OPEN4_SHARE_ACCESS_READ,
                       deny=OPEN4_SHARE_DENY_WRITE,
                       seqid=None):
        if seqid is None: seqid = self.get_seqid(owner)
        ops = self.use_obj(file)
        ops += [op4.open_downgrade(stateid, seqid, access, deny)]
        res = self.compound(ops)
        self.advance_seqid(owner, res)
        if res.status == NFS4_OK:
            res.stateid = res.resarray[-1].switch.switch.open_stateid
        return res

    def write_file(self, file, data, offset=0, stateid=stateid4(0, b''),
                   how=FILE_SYNC4):
        ops = self.use_obj(file)
        ops += [op4.write(stateid, offset, how, data)]
        res = self.compound(ops)
        if res.status == NFS4_OK:
            res.count = res.resarray[-1].switch.switch.count
            res.committed = res.resarray[-1].switch.switch.committed
        return res

    def read_file(self, file, offset=0, count=2048, stateid=stateid4(0, b'')):
        ops =  self.use_obj(file)
        ops += [self.read(offset, count, stateid)]
        res = self.compound(ops)
        if res.status == NFS4_OK:
            res.eof = res.resarray[-1].switch.switch.eof
            res.data = res.resarray[-1].switch.switch.data
        return res

    def lock_file(self, openowner, file, openstateid,
                  offset=0, len=0xffffffffffffffff, type=WRITE_LT,
                  lockseqid=0, openseqid=None, lockowner=None):
        """Lock the file in fh using owner for the first time

        file can be either a fh or a path"""

        if lockowner is None:
            lockowner = b"lockowner_%f" % time.time()
        if openseqid is None: openseqid = self.get_seqid(openowner)
        ops = self.use_obj(file)
        nfs4_lock_owner = lock_owner4(self.clientid, lockowner)
        nfs4_open_owner = open_to_lock_owner4(openseqid, openstateid,
                                              lockseqid, nfs4_lock_owner)
        locker = locker4(TRUE, open_owner=nfs4_open_owner)
        ops += [op4.lock(type, FALSE, offset, len, locker)]
        res = self.compound(ops)
        self.advance_seqid(openowner, res)
        if res.status == NFS4_OK:
            res.lockid = res.resarray[-1].switch.switch.lock_stateid
        return res

    def relock_file(self, seqid, fh, stateid,
                    offset=0, len=0xffffffffffffffff, type=WRITE_LT):
        """Lock the file using stateid and seqid from previous lock operation
        """
        ops = [op4.putfh(fh)]
        existing_lock_owner = exist_lock_owner4(stateid, seqid)
        locker = locker4(FALSE, lock_owner=existing_lock_owner)
        ops += [op4.lock(type, FALSE, offset, len, locker)]
        res = self.compound(ops)
        if res.status==NFS4_OK:
            res.lockid = res.resarray[-1].switch.switch.lock_stateid
        return res

    def unlock_file(self, seqid, file, stateid,
                    offset=0, len=0xffffffffffffffff):
        ops = self.use_obj(file)
        ops += [op4.locku(READ_LT, seqid, stateid, offset, len)]
        res = self.compound(ops)
        if res.status==NFS4_OK:
            res.lockid = res.resarray[-1].switch.lock_stateid
        return res

    def lock_test(self, file, offset=0, len=0xffffffffffffffff, type=WRITE_LT,
                  tester=b"tester"):
        ops = self.use_obj(file)
        test_owner = lock_owner4(self.clientid, tester)
        ops += [op4.lockt(type, offset, len, test_owner)]
        return self.compound(ops)

    def close_file(self, owner, fh, stateid, seqid=None):
        """close the given file"""
        if seqid is None: seqid = self.get_seqid(owner)
        if fh is None:
            ops = []
        else:
            ops = [op4.putfh(fh)]
        ops += [op4.close(seqid, stateid)]
        res = self.compound(ops)
        self.advance_seqid(owner, res)
        return res

    def commit_file(self, file, offset=0, count=0):
        ops = self.use_obj(file)
        ops += [op4.commit(offset, count)]
        return self.compound(ops)

    def maketree(self, tree, root=None, owner=None):
        if owner is None:
            owner = tree[0]
            if type(owner) is list:
                owner = owner[0]
        if root is None:
            root = self.homedir
            tree = [tree]
        for obj in tree:
            if type(obj) is list:
                res = self.create_obj(root + [obj[0]])
                check_result(res)
                self.maketree(obj[1:], root + [obj[0]], owner)
            else:
                self.create_confirm(owner, root + [obj])

#############################################################

def _getname(owner, path):
    if path is None:
        return owner
    else:
        return b'/' + b'/'.join(path)

def check_result(res, msg=None):
    """Verify that a COMPOUND call was successful,
    raise BadCompoundRes otherwise
    """
    if not res.status:
        return

    # If there was an error, it should be the last operation.
    if res.resarray:
        resop = res.resarray[-1].resop
    else:
        resop = None
    raise BadCompoundRes(resop, res.status, msg)

def get_attr_name(bitnum):
    """Return string corresponding to attribute bitnum"""
    return get_bitnumattr_dict().get(bitnum, "Unknown_%r" % bitnum)

_cache_attrbitnum = {}
def get_attrbitnum_dict():
    """Get dictionary with attribute bit positions.

    Note: This function uses introspection. It assumes an entry
    in nfs4_const.py is an attribute iff it is named FATTR4_<something>.

    Returns {"type": 1, "fh_expire_type": 2,  "change": 3 ...}
    """

    if _cache_attrbitnum:
        return _cache_attrbitnum
    for name in dir(nfs4_const):
        if name.startswith("FATTR4_"):
            value = getattr(nfs4_const, name)
            # Sanity checking. Must be integer.
            assert(type(value) is int)
            attrname = name[7:].lower()
            _cache_attrbitnum[attrname] = value
    return _cache_attrbitnum

_cache_bitnumattr = {}
def get_bitnumattr_dict():
    """Get dictionary with attribute bit positions.

    Note: This function uses introspection. It assumes an entry
    in nfs4_const.py is an attribute iff it is named FATTR4_<something>.
    Returns { 1: "type", 2: "fh_expire_type", 3: "change", ...}
    """

    if _cache_bitnumattr:
        return _cache_bitnumattr
    for name in dir(nfs4_const):
        if name.startswith("FATTR4_"):
            value = getattr(nfs4_const, name)
            # Sanity checking. Must be integer.
            assert(type(value) is int)
            attrname = name[7:].lower()
            _cache_bitnumattr[value] = attrname
    return _cache_bitnumattr

def get_attrpackers(packer):
    """Get dictionary with attribute packers of form {bitnum:function}

    Note: This function uses introspection. It depends on that nfs4_pack.py
    has methods for every packer.pack_fattr4_<attribute>.
    """
    out = {}
    dict = get_attrbitnum_dict()
    for name in dir(nfs4_pack.NFS4Packer):
        if name.startswith("pack_fattr4_"):
            # pack_fattr4 is 12 chars.
            attrname = name[12:]
            out[dict[attrname]] = getattr(packer, name)
    return out

def get_attrunpacker(unpacker):
    """Get dictionary with attribute unpackers of form {bitnum:funct}

    Note: This function uses introspection. It depends on that nfs4_pack.py
    has methods for every unpacker.unpack_fattr4_<attribute>.

    """
    attrunpackers = {}
    for name in dir(FancyNFS4Unpacker):
        if name.startswith("unpack_fattr4_"):
            # unpack_fattr4_ is 14 chars.
            attrname = name[14:]
            bitnum = get_attrbitnum_dict()[attrname]
            attrunpackers[bitnum] = getattr(unpacker, name)

    return attrunpackers

_cache_packer = FancyNFS4Packer()
_cache_attrpackers = get_attrpackers(_cache_packer)

def dict2fattr(dict):
    """Convert a dictionary of form {numb:value} to a fattr4 object.

    Returns a fattr4 object.
    """

    attrs = sorted(dict.keys())

    attr_vals = b""
    packer = _cache_packer
    attrpackers = _cache_attrpackers

    for attr in attrs:
        value = dict[attr]
        packerfun = attrpackers[attr];
        packer.reset()
        packerfun(value)
        attr_vals += packer.get_buffer()
    attrmask = list2bitmap(attrs)
    return fattr4(attrmask, attr_vals);

def fattr2dict(obj):
    """Convert a fattr4 object to a dictionary with attribute name and values.

    Returns a dictionary of form {bitnum:value}
    """

    result = {}
    unpacker = FancyNFS4Unpacker(obj.attr_vals)
    list = bitmap2list(obj.attrmask)
    for bitnum in list:
        result[bitnum] = get_attrunpacker(unpacker)[bitnum]()
    unpacker.done()
    return result

def list2bitmap(list):
    """Construct a bitmap from a list of bit numbers"""
    mask = 0
    for bit in list:
        mask |= 1 << bit
    return mask

def bitmap2list(bitmap):
    """Return (sorted) list of bit numbers set in bitmap"""
    out = []
    bitnum = 0
    while bitmap:
        if bitmap & 1:
            out.append(bitnum)
        bitnum += 1
        bitmap >>= 1
    return out

def parse_nfs_url(url):
    """Parse [nfs://]host:port/path, format taken from rfc 2224
       multipath addr:port pair are as such:

      $ip1:$port1,$ip2:$port2..

    Returns triple server, port, path.
    """
    p = re.compile(r"""
    (?:nfs://)?               # Ignore an optionally prepended 'nfs://'
    (?P<servers>[^/]+)
    (?P<path>/.*)?            # set path=everything else, must start with /
    $
    """, re.VERBOSE)

    m = p.match(url)
    if m:
        servers = m.group('servers')
        server_list = []

        for server in servers.split(','):
            server = server.strip()

            idx = server.rfind(':')
            bracket_idx = server.rfind(']')

            # the first : is before ipv6 addr ] -> no port specified
            if bracket_idx > idx:
                idx = -1

            if idx >= 0:
                host = server[:idx]
                port = server[idx+1:]
            else:
                host = server
                port = None

            # remove brackets around IPv6 addrs, if they exist
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]

            port = (2049 if not port else int(port))
            server_list.append((host, port))

        path = os.fsencode(m.group('path'))
        return tuple(server_list), path
    else:
        raise ValueError("Error parsing NFS URL: %s" % url)
