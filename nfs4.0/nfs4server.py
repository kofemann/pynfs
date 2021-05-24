#!/usr/bin/env python3
#
# nfs4server.py - NFS4 server in python
#
# Written by Martin Murray <mmurray@deepthought.org>
# and        Fred Isaman   <iisaman@citi.umich.edu>
# Copyright (C) 2001 University of Michigan, Center for
#                    Information Technology Integration
#


try:
    import psyco
    psyco.full()
except:
    pass

import sys
if sys.hexversion < 0x02070000:
    print("Requires python 2.7 or higher")
    sys.exit(1)
import os
# Allow to be run stright from package root
if  __name__ == "__main__":
    if os.path.isfile(os.path.join(sys.path[0], 'lib', 'testmod.py')):
        sys.path.insert(1, os.path.join(sys.path[0], 'lib'))

from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
import xdrdef.nfs4_pack as nfs4_pack
import rpc.rpc as rpc
import nfs4lib
import time, StringIO, random, traceback, codecs
import StringIO
import nfs4state
from nfs4state import NFS4Error, printverf
from xdrlib import Error as XDRError

unacceptable_names = [ "", ".", ".." ]
unacceptable_characters = [ "/", "~", "#", ]
#unacceptable_unicode_values = [ 0xd800, 0xdb7f, 0xdb80, 0xdb80, 0xdbff, 0xdc00, 0xdf80, 0xdfff, 0xFFFE, 0xFFFF ];

def verify_name(name):
    """Check potential filename and return appropriate error code"""
    if len(name) == 0:
        return NFS4ERR_INVAL
    if len(name) > NFS4_FHSIZE:
        return NFS4ERR_NAMETOOLONG
    if name in unacceptable_names:
        return NFS4ERR_BADNAME
    for character in unacceptable_characters:
        if character in name:
            return NFS4ERR_BADCHAR
    if not verify_utf8(name):
        return NFS4ERR_INVAL
    return NFS4_OK

def verify_utf8(str):
    """Returns True if str is valid utf8, False otherwise"""
    try:
        ustr = codecs.utf_8_decode(str)
        return True
    except UnicodeError:
        return False

def access2string(access):
    ret = []
    if access & ACCESS4_READ:
        ret.append("ACCESS4_READ")
    if access & ACCESS4_LOOKUP:
        ret.append("ACCESS4_LOOKUP")
    if access & ACCESS4_MODIFY:
        ret.append("ACCESS4_MODIFY")
    if access & ACCESS4_EXTEND:
        ret.append("ACCESS4_EXTEND")
    if access & ACCESS4_DELETE:
        ret.append("ACCESS4_DELETE")
    if access & ACCESS4_EXECUTE:
        ret.append("ACCESS4_EXECUTE")
    return ' | '.join(ret)

def simple_error(error, *args):
    """Called from function O_<Name>, sets up and returns a simple error response"""
    name = sys._getframe(1).f_code.co_name # Name of calling function
    try:
        if name.startswith("op_"):
            command = name[3:]
            res = globals()[command.upper() + "4res"](error, *args);
            argop4 = nfs_resop4(globals()["OP_" + command.upper()])
            setattr(argop4, "op" + command, res)
            return (error, argop4)
    except KeyError:
        pass
    raise RuntimeError("Bad caller name %s" % name)

class NFS4Server(rpc.RPCServer):
    def __init__(self, rootfh, host, port, pubfh = None):
        rpc.RPCServer.__init__(self, prog=NFS4_PROGRAM, vers=NFS_V4,
                               host=host, port=port)
        self.nfs4packer = nfs4lib.FancyNFS4Packer()
        self.nfs4unpacker = nfs4lib.FancyNFS4Unpacker('')
        self.state = nfs4state.NFSServerState(rootfh)
        self.fhcache = {}
        self.rootfh = rootfh
        self.pubfh = pubfh
        self.verfnum = 0

    def handle_0(self, data, cred):
        print
        print("******** TCP RPC NULL CALL ********")
        print("  flavor = %i" % cred.flavor)
        if cred.flavor == rpc.RPCSEC_GSS:
            gss = self.security[cred.flavor]
            body = gss.read_cred(cred.body)
            if body.gss_proc:
                return gss.handle_proc(body, data)
        if data != '':
            print("  ERROR - unexpected data")
            return rpc.GARBAGE_ARGS, ''
        else:
            return rpc.SUCCESS, ''

    def handle_1(self, data, cred):
        self.nfs4unpacker.reset(data)
        print
        print("********** TCP RPC CALL ***********")
        ok, results, tag = self.O_Compound()
        try:
            self.nfs4unpacker.done()
        except XDRError:
            print(repr(self.nfs4unpacker.get_buffer()))

            raise
            return rpc.GARBAGE_ARGS, ''
        cmp4res = COMPOUND4res(ok, tag, results)
        self.nfs4packer.reset()
        self.nfs4packer.pack_COMPOUND4res(cmp4res)
        return rpc.SUCCESS, self.nfs4packer.get_buffer()

    def nextverf(self):
        """Return a verifier not previously used by server"""
        self.verfnum += 1
        return nfs4state.packnumber(self.verfnum)

    def prep_client(self):
        self.curr_fh = None
        self.saved_fh = None

    def check_replay(self, op, replay):
        """Pull appropriate info for a replay attempt"""
        fh, args, oldop = replay
        p = nfs4lib.FancyNFS4Packer()
        p.pack_nfs_argop4(op)
        newstr = p.get_buffer()
        p.reset()
        p.pack_nfs_argop4(oldop)
        oldstr = p.get_buffer()
        if oldstr == newstr: # Sadly, op == oldop won't work
            return (fh, args)
        else:
            return (None, (NFS4ERR_BAD_SEQID,))

    def O_Compound(self):
        tag = ''
        try:
            cmp4args = self.nfs4unpacker.unpack_COMPOUND4args()
            tag = cmp4args.tag
        except: # [XDRError, StandardError]:
            #print("ERROR")
            #raise
            return NFS4ERR_BADXDR, [], tag
        print("TCP NFSv4 COMPOUND call, tag: %s, n_ops: %d" % \
              (repr(tag), len(cmp4args.argarray)))
        if cmp4args.minorversion != 0:
            return NFS4ERR_MINOR_VERS_MISMATCH, [], tag
        if not verify_utf8(tag):
            return NFS4ERR_INVAL, [], tag
        self.prep_client()
        results = []
        ok = NFS4_OK
        for op in cmp4args.argarray:
            opname = nfs_opnum4.get(op.argop, 'op_illegal')
            print("*** %s (%d) ***" % (opname, op.argop))
            ok, result = getattr(self, opname.lower())(op)
            results += [ result ]
            if ok != NFS4_OK:
                print(" ! error %s" % nfsstat4[ok])
                break
        print("Replying. Status %s (%d)" % (nfsstat4[ok], ok))
        return (ok, results, tag)

    # FIXME
    def op_access(self, op):
        print("  CURRENT FILEHANDLE: %s" % self.curr_fh)
        print("  REQUESTED ACCESS: %s" % access2string(op.opaccess.access))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        all = ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | \
            ACCESS4_EXTEND | ACCESS4_DELETE | ACCESS4_EXECUTE
        all = ~all
        if op.opaccess.access & all > 0:
            print("!!!! Received invalid ACCESS bits in op.opaccess.access")
            return simple_error(NFS4ERR_INVAL)
        a4_supported = self.curr_fh.supported_access()
        # according to page 140 of 3530, we only return the supported
        # bitmask with values that were requested by the client.
        a4_supported = op.opaccess.access & a4_supported
        a4_access = self.curr_fh.evaluate_access()
        a4_access = op.opaccess.access & a4_access # bitwise and
        print("  RESULT SUPPORTED: %s" % access2string(a4_supported))
        print("  RESULT ACCESS: %s" % access2string(a4_access))
        a4resok = ACCESS4resok(a4_supported, a4_access)
        return simple_error(NFS4_OK, a4resok)

    def op_close(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        print("  SEQID: %i" % op.opclose.seqid)
        stateid = op.opclose.open_stateid
        try:
            replay = self.state.check_seqid(stateid, op.opclose.seqid)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                print("Replay args = %s"%str(args))
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            print("  CLOSE fh", self.curr_fh.handle)
            self.state.close(stateid)
        except NFS4Error as e:
            self.state.advance_seqid(stateid, op, (e.code,))
            return simple_error(e.code)
        # Return a garbage state id
        sid4 = stateid4(0, '')
        self.state.advance_seqid(stateid, op, (NFS4_OK, sid4), self.curr_fh)
        return simple_error(NFS4_OK, sid4)

    # Note: since currently using ram based fs, we lie here (and in write)
    # and pretend all operations are FILE_SYNC4
    def op_commit(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_ISDIR)
        if self.curr_fh.get_type() != NF4REG:
            return simple_error(NFS4ERR_INVAL)
        if op.opcommit.offset + op.opcommit.count >= 0x10000000000000000:
            return simple_error(NFS4ERR_INVAL)
        c4resok = COMMIT4resok(self.state.write_verifier)
        return simple_error(NFS4_OK, c4resok)

    def op_create(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        e = verify_name(op.opcreate.objname)
        if e: return simple_error(e)
        if not self.curr_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        if not self.curr_fh.lookup(op.opcreate.objname) is None:
            return simple_error(NFS4ERR_EXIST)
        if not (NF4DIR <= op.opcreate.objtype.type <= NF4FIFO):
            return simple_error(NFS4ERR_BADTYPE)
        try:
            old_cinfo = self.curr_fh.fattr4_change
            attrs = op.opcreate.createattrs
            print(attrs)
            attrset = self.curr_fh.create(op.opcreate.objname, op.opcreate.objtype, attrs)
            new_cinfo = self.curr_fh.fattr4_change
            self.curr_fh = self.curr_fh.lookup(op.opcreate.objname)
        except NFS4Error as e:
            return simple_error(e.code)
        cin4 = change_info4(before=old_cinfo, after=new_cinfo, atomic=1)
        c4resok = CREATE4resok(cinfo=cin4, attrset = attrset)
        return simple_error(NFS4_OK, c4resok)

    # FIXME: have it actually do something
    def op_delegpurge(self, op):
        return simple_error(NFS4ERR_NOTSUPP)

    # FIXME: have it actually do something
    def op_delegreturn(self, op):
        return simple_error(NFS4ERR_NOTSUPP)

    def op_getattr(self, op):
        print("  ATTRMASK: %s" % [nfs4lib.get_attr_name(bit) for bit in nfs4lib.bitmap2list(op.opgetattr.attr_request)])
        try:
            if not self.curr_fh:
                return simple_error(NFS4ERR_NOFILEHANDLE)
            attrs = nfs4lib.bitmap2list(op.opgetattr.attr_request)
            attrvals = self.curr_fh.get_attributes(attrs)
        except NFS4Error as e:
            return simple_error(e.code)
        garesok = GETATTR4resok(attrvals)
        return simple_error(NFS4_OK, garesok)

    def op_getfh(self, op):
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        print("  FILEHANDLE %s" % self.curr_fh.handle)
        # XXX BUG - fhcache not set on getattr or readdir(getattr)
        self.fhcache[self.curr_fh.handle] = self.curr_fh
        confirmres = GETFH4resok(str(self.curr_fh.handle))
        return simple_error(NFS4_OK, confirmres)

    def op_link(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        print("  SOURCE OBJECT %s" % op.oplink.newname)
        if self.curr_fh is None or self.saved_fh is None:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        if self.saved_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_ISDIR)
        e = verify_name(op.oplink.newname)
        if e: return simple_error(e)
        if self.curr_fh.lookup(op.oplink.newname):
            return simple_error(NFS4ERR_EXIST)
        ci_old = self.curr_fh.fattr4_change
        self.curr_fh.hardlink(self.saved_fh, op.oplink.newname)
        ci_new = self.curr_fh.fattr4_change
        l4_cinfo = change_info4(1, ci_old, ci_new)
        l4resok = LINK4resok(l4_cinfo)
        return simple_error(NFS4_OK, l4resok)

    def op_lock(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        try:
            replay = None
            if op.oplock.locker.new_lock_owner:
                owner = op.oplock.locker.open_owner.lock_owner
                seqid = op.oplock.locker.open_owner.lock_seqid
                openstateid = op.oplock.locker.open_owner.open_stateid
                openseqid = op.oplock.locker.open_owner.open_seqid
                replay = self.state.check_seqid(openstateid, openseqid)
            else:
                owner = op.oplock.locker.lock_owner.lock_stateid
                seqid = op.oplock.locker.lock_owner.lock_seqid
                openstateid = None
                replay = self.state.check_seqid(owner, seqid)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            if op.oplock.reclaim:
                raise NFS4Error(NFS4ERR_NO_GRACE)
            if op.oplock.locker.new_lock_owner:
                self.state.new_lockowner(op.oplock.locker.open_owner)
            stateid = self.state.lock(self.curr_fh, owner, op.oplock.locktype,
                                      op.oplock.offset, op.oplock.length)
        except NFS4Error as e:
            if op.oplock.locker.new_lock_owner:
                # FIXME - a bug? compare with replay=check_seqid() above
                self.state.advance_seqid(openstateid, op, (e.code,))
            self.state.advance_seqid(owner, op, (e.code, None, e.lock_denied))
            return simple_error(e.code, None, e.lock_denied)
        l4resok = LOCK4resok(stateid)
        if op.oplock.locker.new_lock_owner:
            self.state.advance_seqid(openstateid, op, (NFS4_OK,))
        self.state.advance_seqid(owner, op, (NFS4_OK, l4resok), self.curr_fh)
        return simple_error(NFS4_OK, l4resok)

    def op_lockt(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))

        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_ISDIR)
        if self.curr_fh.get_type() != NF4REG:
            return simple_error(NFS4ERR_INVAL)
        try:
            self.state.testlock(self.curr_fh,
                                op.oplockt.owner, op.oplockt.locktype,
                                op.oplockt.offset, op.oplockt.length)
        except NFS4Error as e:
            return simple_error(e.code, e.lock_denied)
        return simple_error(NFS4_OK)

    def op_locku(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        stateid = op.oplocku.lock_stateid
        try:
            replay = self.state.check_seqid(stateid, op.oplocku.seqid)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            sid = self.state.unlock(self.curr_fh, stateid, op.oplocku.locktype,
                                    op.oplocku.offset, op.oplocku.length)
        except NFS4Error as e:
            self.state.advance_seqid(stateid, op, (e.code,))
            return simple_error(e.code)
        self.state.advance_seqid(stateid, op, (NFS4_OK, sid), self.curr_fh)
        return simple_error(NFS4_OK, sid)

    def op_lookup(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        print("  REQUESTED OBJECT %s" % op.oplookup.objname)

        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() == NF4LNK:
            return simple_error(NFS4ERR_SYMLINK)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        e = verify_name(op.oplookup.objname)
        if e: return simple_error(e)
        file = self.curr_fh.lookup(op.oplookup.objname)
        if file is None:
            return simple_error(NFS4ERR_NOENT)
        self.curr_fh = file
        return simple_error(NFS4_OK)

    def op_lookupp(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        self.curr_fh = self.curr_fh.do_lookupp()
        print("  PARENT FILEHANDLE %s" % repr(self.curr_fh))
        if self.curr_fh is None:
            return simple_error(NFS4ERR_NOENT)
        return simple_error(NFS4_OK)

    def op_nverify(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        try:
            attrreq = op.opnverify.obj_attributes
            if FATTR4_RDATTR_ERROR in attrreq:
                return simple_error(NFS4ERR_INVAL)
            attrvals = self.curr_fh.get_attributes(attrreq.keys(), ignore=False)
        except NFS4Error as e:
            return simple_error(e.code)
        if attrvals == attrreq:
            return simple_error(NFS4ERR_SAME)
        else:
            return simple_error(NFS4_OK)

    def op_open(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        print("  SEQID: %i" % op.opopen.seqid)
        owner = op.opopen.owner
        print("  CLIENTID: %d" % owner.clientid)
        print("  OWNER: '%s'" % repr(owner.owner))
        try:
            if not self.state.confirmed.exists(c=owner.clientid):
                if self.state.unconfirmed.exists(c=owner.clientid):
                    raise NFS4Error(NFS4ERR_STALE_CLIENTID)
                else:
                    raise NFS4Error(NFS4ERR_BADOWNER)
            replay = self.state.check_seqid(owner, op.opopen.seqid, False)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            if op.opopen.claim.claim == CLAIM_PREVIOUS:
                raise NFS4Error(NFS4ERR_NO_GRACE)
            if op.opopen.claim.claim in [CLAIM_DELEGATE_CUR, CLAIM_DELEGATE_PREV]:
                raise NFS4Error(NFS4ERR_NOTSUPP)
            if self.curr_fh.get_type() != NF4DIR:
                raise NFS4Error(NFS4ERR_NOTDIR)
            filename = op.opopen.claim.file
            print("  FILE %s" % filename)
            e = verify_name(filename)
            if e: raise NFS4Error(e)
            # At this point we know it is CLAIM_NULL with valid filename and cfh
            attrset = 0
            ci_old = self.curr_fh.fattr4_change
            if op.opopen.openhow.opentype == OPEN4_CREATE:
                print("  CREATING FILE.")
                type_reg = createtype4(NF4REG)
                existing = self.curr_fh.lookup(filename)
                if existing is not None:
                    if existing.get_type() == NF4DIR:
                        raise NFS4Error(NFS4ERR_ISDIR)
                    if existing.get_type() == NF4LNK:
                        raise NFS4Error(NFS4ERR_SYMLINK)
                    if existing.get_type() != NF4REG:
                        raise NFS4Error(NFS4ERR_INVAL)
                if op.opopen.openhow.how.mode == EXCLUSIVE4:
                    if existing is not None:
                        if not existing.match_create_verf(op.opopen.openhow.how.createverf):
                            raise NFS4Error(NFS4ERR_EXIST)
                        # Now break out and use existing as is
                    else:
                        # Create file with no attrs and set verifier
                        attrset = self.curr_fh.create(filename, type_reg)
                        existing = self.curr_fh.lookup(filename)
                        existing.create_verf = op.opopen.openhow.how.createverf
                else:
                    attrs = op.opopen.openhow.how.createattrs
                    if existing is not None:
                        if op.opopen.openhow.how.mode == GUARDED4:
                            raise NFS4Error(NFS4ERR_EXIST)
                        # with an existing file ignore attrs except size=0
                        if FATTR4_SIZE in attrs and attrs[FATTR4_SIZE]==0:
                            attrset = existing.set_attributes(attrdict={FATTR4_SIZE:0})
                        # Now break out and use existing as is
                    else:
                        attrset = self.curr_fh.create(filename, type_reg, attrs)
                        existing = self.curr_fh.lookup(filename)
            else:
                print("  OPENING EXISTING FILE.")
                existing = self.curr_fh.lookup(filename)
                if existing is None:
                    raise NFS4Error(NFS4ERR_NOENT)
                if existing.get_type() == NF4DIR:
                    raise NFS4Error(NFS4ERR_ISDIR)
                if existing.get_type() == NF4LNK:
                    raise NFS4Error(NFS4ERR_SYMLINK)
                if existing.get_type() != NF4REG:
                    raise NFS4Error(NFS4ERR_INVAL)
            # 'existing'  now points to a valid file, so check and set shares
            sid, flags = self.state.open(existing, owner,
                                  op.opopen.share_access, op.opopen.share_deny)
        except NFS4Error as e:
            print("Open error")
            self.state.advance_seqid(owner, op, (e.code,))
            return simple_error(e.code)
        ci_new = self.curr_fh.fattr4_change
        cif4 = change_info4(1, ci_old, ci_new)
        od4 = open_delegation4(delegation_type=OPEN_DELEGATE_NONE)
        o4rok = OPEN4resok(stateid=sid, cinfo=cif4, rflags=flags,
                           attrset=attrset, delegation=od4)
        self.curr_fh = self.curr_fh.lookup(filename)
        self.state.advance_seqid(owner, op, (NFS4_OK, o4rok), self.curr_fh)
        return simple_error(NFS4_OK, o4rok)

    # FIXME: actually open the attr directory, change the filehandle
    def op_openattr(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        return simple_error(NFS4ERR_NOTSUPP)

    def op_open_confirm(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        print("  SEQID: %i" % op.opopen_confirm.seqid)
        stateid = op.opopen_confirm.open_stateid
        try:
            replay = self.state.check_seqid(stateid, op.opopen_confirm.seqid,
                                            open_confirm=True)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            if self.curr_fh.get_type() == NF4DIR:
                raise NFS4Error(NFS4ERR_ISDIR)
            if self.curr_fh.get_type() != NF4REG:
                raise NFS4Error(NFS4ERR_INVAL)
            sid = self.state.confirm(self.curr_fh, stateid)
        except NFS4Error as e:
            self.state.advance_seqid(stateid, op, (e.code,))
            return simple_error(e.code)
        oc4resok = OPEN_CONFIRM4resok(sid)
        self.state.advance_seqid(stateid, op, (NFS4_OK, oc4resok), self.curr_fh)
        return simple_error(NFS4_OK, oc4resok)

    def op_open_downgrade(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        stateid = op.opopen_downgrade.open_stateid
        try:
            replay = self.state.check_seqid(stateid, op.opopen_downgrade.seqid)
            if replay:
                self.curr_fh, args = self.check_replay(op, replay)
                return simple_error(*args)
            # Note must cache response, so need to call raise instead of return
            if not self.curr_fh:
                raise NFS4Error(NFS4ERR_NOFILEHANDLE)
            if self.curr_fh.get_type() != NF4REG:
                raise NFS4Error(NFS4ERR_INVAL)
            sid = self.state.downgrade(self.curr_fh, stateid,
                                       op.opopen_downgrade.share_access,
                                       op.opopen_downgrade.share_deny)
        except NFS4Error as e:
            self.state.advance_seqid(stateid, op, (e.code,))
            return simple_error(e.code)
        od4resok = OPEN_DOWNGRADE4resok(sid)
        self.state.advance_seqid(stateid, op, (NFS4_OK, od4resok), self.curr_fh)
        return simple_error(NFS4_OK, od4resok)

    def op_putfh(self, op):
        print("  FILEHANDLE '%s'" % repr(op.opputfh.object))
        # check access!
        if not op.opputfh.object in self.fhcache:
            return simple_error(NFS4ERR_BADHANDLE)
        self.curr_fh = self.fhcache[op.opputfh.object]
        return simple_error(NFS4_OK)

    def op_putpubfh(self, op):
        print("  NEW FILEHANDLE %s" % repr(self.curr_fh))
        if self.pubfh is None:
            return simple_error(NFS4ERR_NOTSUPP)
        self.curr_fh = self.pubfh
        return simple_error(NFS4_OK)

    def op_putrootfh(self, op):
        print("  NEW FILEHANDLE %s" % repr(self.curr_fh))
        self.curr_fh = self.rootfh
        return simple_error(NFS4_OK)

    def op_read(self, op):
        offset = op.opread.offset
        count = op.opread.count
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        print("  OFFSET: %d COUNT %d" % (offset, count))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_ISDIR)
        if self.curr_fh.get_type() != NF4REG:
            return simple_error(NFS4ERR_INVAL)
        try:
            self.state.check_read(self.curr_fh, op.opread.stateid,
                                  offset, count)
            read_data = self.curr_fh.read(offset, count)
            print("  READ DATA: len=%i" % len(read_data))
        except NFS4Error as e:
            return simple_error(e.code)
        if len(read_data) < count:
            read_eof = 1
        else:
            read_eof = 0
        r4rok = READ4resok(read_eof, read_data)
        return simple_error(NFS4_OK, r4rok)

    def op_readdir(self, op):
        # We ignore dircount hint
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        print("  COOKIEVERF: %s, %s" % ( repr(op.opreaddir.cookieverf), repr(op.opreaddir.cookie)))
        print("  DIRCOUNT: %d MAXCOUNT: %d" % ( op.opreaddir.dircount, op.opreaddir.maxcount))
        print("  ATTRMASK: %s" % [nfs4lib.get_attr_name(bit) for bit in nfs4lib.bitmap2list(op.opreaddir.attr_request)])
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        if op.opreaddir.cookie in [1,2]:
            return simple_error(NFS4ERR_BAD_COOKIE)
        if op.opreaddir.maxcount == 0:
            return simple_error(NFS4ERR_TOOSMALL)
        zeroverf = '\x00\x00\x00\x00\x00\x00\x00\x00'
        if op.opreaddir.cookie == 0 and op.opreaddir.cookieverf != zeroverf:
            return simple_error(NFS4ERR_BAD_COOKIE)
        try:
            verifier = self.curr_fh.getdirverf()
            if op.opreaddir.cookie != 0:
                if op.opreaddir.cookieverf != verifier:
                    return simple_error(NFS4ERR_NOT_SAME)
            try:
                dirlist = self.curr_fh.read_dir(op.opreaddir.cookie)
            except IndexError:
                return simple_error(NFS4ERR_BAD_COOKIE)
            attrs = nfs4lib.bitmap2list(op.opreaddir.attr_request)
            entries = []
            bytecnt = 0
            packer = nfs4lib.FancyNFS4Packer()
            for entry in dirlist:
                # Get file attributes
                try:
                    attrvals = entry.fh.get_attributes(attrs)
                except NFS4Error:
                    if FATTR4_RDATTR_ERROR not in attrs: raise
                    attrvals = entry.fh.get_attributes([FATTR4_RDATTR_ERROR])
                entry.attr = attrvals
                # Compute size of XDR encoding
                e4 = entry4(entry.cookie, entry.name, entry.attr, [])
                packer.reset()
                packer.pack_entry4(e4)
                # Make sure returned value not too big
                bytecnt += len(packer.get_buffer())
                if bytecnt > op.opreaddir.maxcount - 16:
                    break
                # Add file to returned entries
                entries.insert(0,entry)
            if (not entries) and dirlist:
                return simple_error(NFS4ERR_TOOSMALL)
            # Encode entries as linked list
            e4 = []
            for entry in entries:
                e4 = [entry4(entry.cookie, entry.name, entry.attr, nextentry=e4)]
            if len(entries) < len(dirlist):
                d4 = dirlist4(e4, eof=0)
            else:
                d4 = dirlist4(e4, eof=1)
        except NFS4Error as e:
            return simple_error(e.code)
        rdresok = READDIR4resok(cookieverf=verifier, reply=d4)
        return simple_error(NFS4_OK, rdresok)

    def op_readlink(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4LNK:
            return simple_error(NFS4ERR_INVAL)
        link_text = self.curr_fh.read_link()
        print("  LINK_TEXT: %s" % link_text)
        rl4resok = READLINK4resok(link_text)
        return simple_error(NFS4_OK, rl4resok)

    def op_remove(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        print("  TARGET: %s" % op.opremove.target)
        #XXX: CHECK ACCESS
        if self.curr_fh is None:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        e = verify_name(op.opremove.target)
        if e: return simple_error(e)
        file = self.curr_fh.lookup(op.opremove.target)
        if file is None:
            return simple_error(NFS4ERR_NOENT)
        if file.get_type() == NF4DIR and not file.is_empty():
            return simple_error(NFS4ERR_NOTEMPTY)
        ci_old = self.curr_fh.fattr4_change
        self.curr_fh.remove(op.opremove.target)
        ci_new = self.curr_fh.fattr4_change
        r4_cinfo = change_info4(1, ci_old, ci_new)
        r4resok = REMOVE4resok(r4_cinfo)
        return simple_error(NFS4_OK, r4resok)

    def op_rename(self, op):
        print("  SAVED FILEHANDLE: %s" % repr(self.saved_fh)  # old dir)
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh) # new dir)
        print("  OLD NAME: %s" % op.oprename.oldname)
        print("  NEW NAME: %s" % op.oprename.newname)
        if self.curr_fh is None or self.saved_fh is None:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        oldname = op.oprename.oldname
        newname = op.oprename.newname
        e = verify_name(oldname)
        if e: return simple_error(e)
        e = verify_name(newname)
        if e: return simple_error(e)
        if self.curr_fh.get_type() != NF4DIR or \
           self.saved_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        source = self.saved_fh.lookup(oldname)
        target = self.curr_fh.lookup(newname)
        if source is None:
            return simple_error(NFS4ERR_NOENT)
        src_cinfo = self.saved_fh.fattr4_change
        targ_cinfo = self.curr_fh.fattr4_change
        skip = False
        # XXX: check access
        if target is not None:
            if (source.get_type()==NF4DIR) != (target.get_type()==NF4DIR):
                # Incompatible types
                return simple_error(NFS4ERR_EXIST)
            if target.get_type()==NF4DIR and not target.is_empty():
                return simple_error(NFS4ERR_EXIST)
            if source == target:
                # Do nothing and return OK
                skip = True
            else:
                # Remove target and continue as if it had never been
                self.curr_fh.remove(newname)
        if not skip: self.curr_fh.rename(self.saved_fh, oldname, newname)
        r4_src_cinfo = change_info4(1, src_cinfo, self.saved_fh.fattr4_change)
        r4_targ_cinfo = change_info4(1, targ_cinfo, self.curr_fh.fattr4_change)
        r4resok = RENAME4resok(r4_src_cinfo, r4_targ_cinfo)
        return simple_error(NFS4_OK, r4resok)

    # FIXME: need to check principal/security as stated in RFC
    def op_renew(self, op):
        try:
            self.state.renew(op.oprenew.clientid)
        except NFS4Error as e:
            return simple_error(e.code)
        return simple_error(NFS4_OK)

    def op_restorefh(self, op):
        print("  SAVED FILEHANDLE: %s" % repr(self.saved_fh))
        if not self.saved_fh:
            return simple_error(NFS4ERR_RESTOREFH)
        self.curr_fh = self.saved_fh
        return simple_error(NFS4_OK)

    def op_savefh(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        self.saved_fh = self.curr_fh
        return simple_error(NFS4_OK)

    # FIXME: no idea how to set up NFS4_OK conditions; actually get sec information
    def op_secinfo(self, op):
        # STUB
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() != NF4DIR:
            return simple_error(NFS4ERR_NOTDIR)
        e = verify_name(op.opsecinfo.name)
        if e: return simple_error(e)
        resok = [secinfo4(0), secinfo4(1)]
        return simple_error(NFS4_OK, resok)

    def op_setattr(self, op):
        print("  CURRENT FILEHANDLE: %s" % repr(self.curr_fh))
        print(op.opsetattr.obj_attributes)
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE, 0)
        try:
            attrdict = op.opsetattr.obj_attributes
            if FATTR4_SIZE in attrdict:
                # This counts as a write, so must do some checking
                if self.curr_fh.get_type() != NF4REG:
                    return simple_error(NFS4ERR_BAD_STATEID, 0)
                oldsize = self.curr_fh.fattr4_size
                newsize = attrdict[FATTR4_SIZE]
                if oldsize <= newsize:
                    offset = oldsize
                    length = newsize - oldsize
                else:
                    offset = newsize
                    length = oldsize - newsize
                self.state.check_write(self.curr_fh, op.opsetattr.stateid,
                                       offset, length)
            attrset = self.curr_fh.set_attributes(attrdict)
        except NFS4Error as e:
            return simple_error(e.code, e.attrs)
        return simple_error(NFS4_OK, attrset)

    def op_setclientid(self, op):
        print("  ID: %s" % ( op.opsetclientid.client.id))
        x = op.opsetclientid.client.id
        v = op.opsetclientid.client.verifier
        k = (op.opsetclientid.callback, op.opsetclientid.callback_ident)
        p = "Stub" # Principal
        # NOTE this makes the assumption that only one entry can match x=x
        entry = self.state.confirmed.find(x=x)
        entry2 = self.state.unconfirmed.find(x=x)
        if entry is None:
            self.state.unconfirmed.remove(x=x)
            c = self.state.new_clientid()
        elif entry.principal != p:
            return simple_error(NFS4ERR_CLID_INUSE)
        elif entry.v == v:
            self.state.unconfirmed.remove(x=x) # Note change from rfc
            c = entry.c
        elif entry2 is None:
            c = self.state.new_clientid()
        elif entry.s != entry2.s: # Note change from rfc
            self.state.unconfirmed.remove(x=x)
            c = self.state.new_clientid()
        else:
            # This should never happen
            return simple_error(NFS4ERR_INVAL)
        s = self.nextverf()
        print("   VERIFIER: %s" % repr(s))
        self.state.unconfirmed.add(v,x,c,k,s,p)
        resok = SETCLIENTID4resok(c, s)
        return simple_error(NFS4_OK, resok)

    def op_setclientid_confirm(self, op):
        c = op.opsetclientid_confirm.clientid
        s = op.opsetclientid_confirm.setclientid_confirm
        p = "Stub" # Principal
        print("  ARGS, clientid %s, verifier %s" % (c, printverf(s)))
        # NOTE this makes the assumption that only one entry can match c=c
        entry = self.state.confirmed.find(c=c)
        entry2 = self.state.unconfirmed.find(c=c)
        if (entry is None or not self.state.confirmed.exists(c=c, s=s)) and \
           (entry2 is None or not self.state.unconfirmed.exists(c=c, s=s)):
            # ie neither matches (**c*s)
            return simple_error(NFS4ERR_STALE_CLIENTID)
        if entry is None and entry2 and entry2.s == s:
            if entry2.principal != p:
                return simple_error(NFS4ERR_CLID_INUSE)
            oldentry = self.state.confirmed.find(x=entry2.x)
            if oldentry is not None:
                self.state.remove_state(oldentry.c)
        elif entry and entry.s == s and not self.state.unconfirmed.exists(v=entry.v, x=entry.x, c=c):
            if entry.principal != p:
                return simple_error(NFS4ERR_CLID_INUSE)
            return simple_error(NFS4_OK)
        elif entry and entry2 and entry.v==entry2.v and  entry.x==entry2.x and entry.s != entry2.s:
            if entry.principal != p or entry2.principal != p:
                return simple_error(NFS4ERR_CLID_INUSE)
        else:
            # This should never happen
            return simple_error(NFS4ERR_INVAL)
        self.state.confirmed.remove(x=entry2.x)
        self.state.confirmed.addentry(entry2)
        self.state.unconfirmed.remove(x=entry2.x)
        self.state.reset_seqid(c)
        return simple_error(NFS4_OK)

    def op_verify(self, op):
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        try:
            attrreq = op.opverify.obj_attributes
            if FATTR4_RDATTR_ERROR in attrreq:
                return simple_error(NFS4ERR_INVAL)
            attrvals = self.curr_fh.get_attributes(attrreq.keys(), ignore=False)
        except NFS4Error as e:
            return simple_error(e.code)
        if attrvals == attrreq:
            return simple_error(NFS4_OK)
        else:
            return simple_error(NFS4ERR_NOT_SAME)

    # Note: since currently using ram based fs, we lie here (and in commit)
    # and pretend all operations are FILE_SYNC4
    def op_write(self, op):
        offset = op.opwrite.offset
        data = op.opwrite.data
        print("  CURRENT FILEHANDLE %s" % repr(self.curr_fh))
        print("  OFFSET: %d COUNT %d" % (offset, len(data)))
        print("  STATEID { seqid: %s other: %s}" % (repr(op.opwrite.stateid.seqid), repr(op.opwrite.stateid.other)))
        if not self.curr_fh:
            return simple_error(NFS4ERR_NOFILEHANDLE)
        if self.curr_fh.get_type() == NF4DIR:
            return simple_error(NFS4ERR_ISDIR)
        if self.curr_fh.get_type() != NF4REG:
            return simple_error(NFS4ERR_INVAL)
        #print("  DATA: %s" % op.opwrite.data)
        try:
            self.state.check_write(self.curr_fh, op.opwrite.stateid,
                                   offset, len(data))
            count = self.curr_fh.write(offset, data)
            print("  wrote %i bytes" % count)
        except NFS4Error as e:
            return simple_error(e.code)
        w4resok = WRITE4resok(count, FILE_SYNC4, self.state.write_verifier)
        return simple_error(NFS4_OK, w4resok)

    # FIXME: actually release the lock owner
    def op_release_lockowner(self, op):
        return simple_error(NFS4ERR_NOTSUPP)

    def op_illegal(self, op):
        return simple_error(NFS4ERR_OP_ILLEGAL)

def startup(host, port):
    rootfh = nfs4state.VirtualHandle()
    server = NFS4Server(rootfh, port=port, host=host, pubfh=rootfh)
    try:
        import rpc.portmap as portmap
        if not portmap.set(NFS4_PROGRAM, NFS_V4, portmap.IPPROTO_TCP, port):
            raise
        #server.register()
    except:
        print("!! unable to register with portmap")
        pass
    print("Python NFSv4 Server, (c) CITI, Regents of the University of Michigan")
    print("Starting Server, root handle: %s" % rootfh )
    server.run()
    try:
        server.unregister()
    except:
        pass

if __name__ == "__main__":
    port = 2049
    server = ''
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    if len(sys.argv) > 1:
        server = sys.argv[1]

    startup(server, port)
