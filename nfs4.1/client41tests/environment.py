#
# environment.py
#
# Requires python 3.2
# 
# Written by Fred Isaman <iisaman@citi.umich.edu>
# Copyright (C) 2004 University of Michigan, Center for 
#                    Information Technology Integration
#

import time
import testmod
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
import rpc.rpc as rpc
import nfs4client
import os
import nfs4lib
import logging
import struct
from rpc.security import AuthSys, AuthGss
from threading import Lock
import nfs_ops
op = nfs_ops.NFS4ops()

log = logging.getLogger("test.env")

class AttrInfo(object):
    def __init__(self, name, access, sample):
        self.name = name
        self.bitnum = nfs4lib.attr2bitnum[name]
        self.mask = 2**self.bitnum
        self.access = access
        self.sample = sample

    def __str__(self):
        return '%s %i %s' % (self.name, self.bitnum, self.access)

    writable = property(lambda self: 'w' in self.access)
    readable = property(lambda self: 'r' in self.access)
    mandatory = property(lambda self: 'm' in self.access)
    readonly = property(lambda self: \
                         'r' in self.access and 'w' not in self.access)
    writeonly = property(lambda self: \
                         'w' in self.access and 'r' not in self.access)

class Environment(testmod.Environment):
    # STUB
    attr_info = [ \
        AttrInfo('supported_attrs', 'rm', []),
        AttrInfo('type', 'rm', 1),
        AttrInfo('fh_expire_type', 'rm', 0),
        AttrInfo('change', 'rm', 0),
        AttrInfo('size', 'rwm', 0),
        AttrInfo('link_support', 'rm', False),
        AttrInfo('symlink_support', 'rm', False),
        AttrInfo('named_attr', 'rm', False),
        AttrInfo('fsid', 'rm', fsid4(0, 0)),
        AttrInfo('unique_handles', 'rm', False),
        AttrInfo('lease_time', 'rm', 0),
        AttrInfo('rdattr_error', 'rm', 0),
        AttrInfo('filehandle', 'rm', 'nonsense'),
        AttrInfo('acl', 'rw', [nfsace4(0,0,0,'EVERYONE@')]),
        AttrInfo('aclsupport', 'r', 0),
        AttrInfo('archive', 'rw', False),
        AttrInfo('cansettime', 'r', False),
        AttrInfo('case_insensitive', 'r', False),
        AttrInfo('case_preserving', 'r', False),
        AttrInfo('chown_restricted', 'r', False),
        AttrInfo('fileid', 'r', 0),
        AttrInfo('files_avail', 'r', 0),
        AttrInfo('files_free', 'r', 0),
        AttrInfo('files_total', 'r', 0),
        # FRED - packer did not complain about missing [] about server
        AttrInfo('fs_locations', 'r',
                 fs_locations4('root',[fs_location4(['server'],'path')])),
        AttrInfo('hidden', 'rw', False),
        AttrInfo('homogeneous', 'r', False),
        AttrInfo('maxfilesize', 'r', 0),
        AttrInfo('maxlink', 'r', 0),
        AttrInfo('maxname', 'r', 0),
        AttrInfo('maxread', 'r', 0),
        AttrInfo('maxwrite', 'r', 0),
        AttrInfo('mimetype', 'rw', 'nonsense'),
        AttrInfo('mode', 'rw', 0),
        AttrInfo('no_trunc', 'r', False),
        AttrInfo('numlinks', 'r', 0),
        AttrInfo('owner', 'rw', 'nonsense'),
        AttrInfo('owner_group', 'rw', 'nonsense'),
        AttrInfo('quota_avail_hard', 'r', 0),
        AttrInfo('quota_avail_soft', 'r', 0),
        AttrInfo('quota_used', 'r', 0),
        AttrInfo('rawdev', 'r', specdata4(0, 0)),
        AttrInfo('space_avail', 'r', 0),
        AttrInfo('space_free', 'r', 0),
        AttrInfo('space_total', 'r', 0),
        AttrInfo('space_used', 'r', 0),
        AttrInfo('system', 'rw', False),
        AttrInfo('time_access', 'r', nfstime4(0, 0)),
        AttrInfo('time_access_set', 'w', settime4(0)),
        AttrInfo('time_backup', 'rw', nfstime4(0, 0)),
        AttrInfo('time_create', 'rw', nfstime4(0, 0)),
        AttrInfo('time_delta', 'r', nfstime4(0, 0)),
        AttrInfo('time_metadata', 'r', nfstime4(0, 0)),
        AttrInfo('time_modify', 'r', nfstime4(0, 0)),
        AttrInfo('time_modify_set', 'w', settime4(0)),
        AttrInfo('mounted_on_fileid', 'r', 0),
        ]

    def __init__(self, opts):
        self._lock = Lock()
        self.opts = opts
        opts.home = opts.path + ['a']
        self.root = os.path.join(os.sep, *opts.path)
        self.home = os.path.join(os.sep, *opts.home)

        self.timestamp = int(time.time())
        self._last_verf = self.timestamp + 1
        self.filedata = "This is the file test data."
        self.linkdata = "/etc/X11"

    def reboot_server(self):
        # echo "1" > $ACTIONS/reboot
        path = os.path.join(self.root, "config", "actions", "reboot")
        fd = open(path, "w")
        fd.write("1")
        fd.close()

    # Message-type ERROR has the form "ERROR" NFS4ERR_XXX ceiling
    def set_error(self, opname, code):
        data = "ERROR %s %i" % (code, 0)
        path = os.path.join(self.root, "config", "ops", opname)
        fd = open(path, "w")
        fd.write(data)
        fd.close()

    def set_error_wait_lease(self, opname, code):
        data = "ERROR %s %i" % (code, 0)
        path = os.path.join(self.root, "config", "serverwide", "lease_time")
        fd = open(path, "r")
        lease = fd.readlines()
        fd.close()
        time.sleep(1)
        path = os.path.join(self.root, "config", "ops", opname)
        fd = open(path, "w")
        fd.write(data)
        print("wait for leasetime: ", lease[1], "seconds")
        fd.close()
        time.sleep(int(lease[1]))

    def set_two_values(self, opname, messagetype, value1, value2):
        # Write the messagetype and values
        path = os.path.join(self.root, "config", "ops", opname)
        fd = open(path, "w")
        data = "%s %s %s" % (messagetype, value1, value2)
        fd.write(data)
        fd.close()
        
    def clear_two_values(self, opname):
        # Return server to normal operation.
        # Write default values
        path = os.path.join(self.root, "config", "ops", opname)
        fd = open(path, "w")
        data = "ERROR %i %i" % (0, 0)
        fd.write(data)
        fd.close()

    def init(self):
        """Run once before any test is run"""
        pass

    def finish(self):
        """Run once after all tests are run"""
        pass

    def startUp(self):
        """Run before each test"""
        pass

    def sleep(self, sec, msg=''):
        """Sleep for given seconds"""
        log.info("Sleeping for %i seconds: %s" % (sec, msg))
        time.sleep(sec)
        log.info("Woke up")

    def new_verifier(self):
        """Returns a never before used verifier"""
        candidate = int(time.time())
        self._lock.acquire()
        try:
            if candidate <= self._last_verf:
                candidate = self._last_verf + 1
            self._last_verf = candidate
        finally:
            self._lock.release()
        return struct.pack('>d', candidate)

    def testname(self, t):
        """Returns a name for the test that is unique between runs"""
        return "%s_%i" % (t.code, self.timestamp)
    
#########################################
debug_fail = False

def fail(msg):
    raise testmod.FailureException(msg)

def check(res, stat=NFS4_OK, msg=None, warnlist=[]):
    #if res.status == stat:
    #    return
    if type(stat) is str:
        raise "You forgot to put 'msg=' in front of check's string arg"
    log.debug("checking %r == %r" % (res, stat))
    if res.status == stat:
        if not (debug_fail and msg):
            return
    desired = nfsstat4[stat]
    received = nfsstat4[res.status]
    if msg:
        failedop_name = msg
    elif res.resarray:
        failedop_name = nfs_opnum4[res.resarray[-1].resop]
    else:
        failedop_name = 'Compound'
    msg = "%s should return %s, instead got %s" % \
          (failedop_name, desired, received)
    if res.status in warnlist:
        raise testmod.WarningException(msg)
    else:
        raise testmod.FailureException(msg)

def checklist(res, statlist, msg=None):
    if res.status in statlist:
        return
    statnames = [nfsstat4[stat] for stat in statlist]
    desired = ' or '.join(statnames)
    if not desired:
        desired = 'one of <none>'
    received = nfsstat4[res.status]
    if msg:
        failedop_name = msg
    elif res.resarray:
        failedop_name = nfs_opnum4[res.resarray[-1].resop]
    else:
        failedop_name = 'Compound'
    msg = "%s should return %s, instead got %s" % \
          (failedop_name, desired, received)
    raise testmod.FailureException(msg)

def checkdict(expected, got, translate={}, failmsg=''):
    if failmsg: failmsg += ': '
    for k in expected:
        if k not in got:
            try:
                name = translate[k]
            except KeyError:
                name = str(k)
            raise testmod.FailureException(failmsg +
                          "For %s expected %s, but no value returned" %
                          (name, str(expected[k])))
        if expected[k] != got[k]:
            try:
                name = translate[k]
            except KeyError:
                name = str(k)
            raise testmod.FailureException(failmsg +
                          "For %s expected %s, got %s" %
                          (name, str(expected[k]), str(got[k])))

def get_invalid_utf8strings():
    """Return a list of invalid ISO10646-UTF-8 strings"""
    # FIXME: More invalid strings.
    return ["\xc0\xc1", # starts two multibyte sequences
            "\xe0\x8a", # terminates a multibyte sequence too early
            "\xc0\xaf", # overlong character"
            "\xfc\x80\x80\x80\x80\xaf", # overlong character
            "\xfc\x80\x80\x80\x80\x80", # NULL
            "\xed\xa0\x80", # UTF-16 surrogate
            "\xed\xbf\xbf", # UTF-16 surrogate
            "\xef\xbf\xbe", # Invalid character U+FFFE
            "\xe3\xc0\xc0", # just mangled.
            "\xc0\x90", # overlong character
            # byte sequences that should never appear at start
            "\x80",
            "\xbf",
            "\xfe",
            "\xff",
            # starts with no ends
            "\xc0 ",
            "\xdf ",
            "\xe0 ",
            "\xef ",
            "\xf0 ",
            "\xf7 ",
            "\xf8 ",
            "\xfb ",
            "\xfc ",
            "\xfd "
            ]

def get_invalid_clientid():
    """Return a (guessed) invalid clientid"""
    return 0

def makeStaleId(stateid):
    """Given a good stateid, makes it stale

    NOTE this looks into server opaque data, thus is very specific
    to the CITI linux server.  All tests which use this function have
    the flag 'staleid'
    """
    boottime = stateid.other[0:4]
    if ord(boottime[0]):
        staletime = b"\0" + boottime[1:4]
    else:
        staletime = b"a" + boottime[1:4]
    stale = stateid4(stateid.seqid , staletime+b"\0\0\0\0\0\0\0\0")
    return stale

def makeBadID(stateid):
    """Given a good stateid, makes it bad

    NOTE this looks into server opaque data, thus is very specific
    to the CITI linux server.  All tests which use this function have
    the flag 'badid'
    """

    boottime = stateid.other[0:4]
    bad = stateid4(stateid.seqid , boottime+b"\0\0\0\0\0\0\0\0")
    return bad

def compareTimes(time1, time2):
    """Compares nfstime4 values

    Returns -1 if time1 < time2
             0 if time1 ==time2
             1 if time1 > time2
    """

    if time1.seconds < time2.seconds:
        return -1
    if time1.seconds > time2.seconds:
        return 1
    if time1.seconds == time2.seconds:
        if time1.nseconds < time2.nseconds:
            return -1
        if time1.nseconds > time2.nseconds:
            return 1
        return 0

#############################################

# Of course, there is no guarantee that this is not a valid session id, but...
bad_sessionid = b"Bad Session Id"



def clean_dir(sess, path):
    stateid = nfs4lib.state00
    # fh = self.do_getfh(path)
    entries = do_readdir(sess, path)
    for e in entries:
        # We separate setattr and remove to avoid an inode locking bug
        ops = use_obj(path + [e.name])
        ops += [op.setattr(stateid, {FATTR4_MODE:0o755})]
        res = sess.compound(ops)
        check(res, msg="Setting mode on %s" % repr(e.name))
        ops = use_obj(path)
        ops += [op.remove(e.name)]
        res = sess.compound(ops)
        if res.status == NFS4ERR_NOTEMPTY:
            clean_dir(sess, path + [e.name])
            res = sess.compound(ops)
        check(res, msg="Trying to remove %s" % repr(e.name))

def do_readdir(sess, file, cookie=0, cookieverf='', attrs=0,
               dircount=4096, maxcount=4096):
    # Since we may not get whole directory listing in one readdir request,
    # loop until we do. For each request result, create a flat list
    # with <entry4> objects.
    log.info("Called do_readdir()")
    entries = []
    baseops = use_obj(file)
    while True:
        readdir_op = op.readdir(cookie, cookieverf, dircount, maxcount, attrs)
        res = sess.compound(baseops + [readdir_op])
        check(res, msg="READDIR with cookie=%i, maxcount=%i" % (cookie, maxcount))
        reply = res.resarray[-1].reply
        if not reply.entries and not reply.eof:
            raise UnexpectedCompoundRes("READDIR had no entries")
        entries.extend(reply.entries)
        if reply.eof:
            break
        cookie = entries[-1].cookie
        cookieverf = res.resarray[-1].cookieverf
    log.info("do_readdir() = %r" % entries)
    return entries

def use_obj(file):
    """File is either None, a fh, or a list of path components"""
    if file is None or file == [None]:
        return []
    elif type(file) is str:
        return [op.putfh(file)]
    else:
        return [op.putrootfh()] + [op.lookup(comp) for comp in file]

def create_obj(sess, path, kind=NF4DIR, attrs={FATTR4_MODE:0o755}):
    """Return ops needed to create given non-file object"""
    # Ensure using createtype4
    if not hasattr(kind, "type"):
        kind = createtype4(kind)
    ops = use_obj(path[:-1]) + [op.create(kind, path[-1], attrs)]
    return sess.compound(ops)

def create_file(sess, owner, path=None, attrs={FATTR4_MODE: 0o644},
                access=OPEN4_SHARE_ACCESS_BOTH,
                deny=OPEN4_SHARE_DENY_NONE,
                mode=GUARDED4, verifier=None, want_deleg=False):
    # Set defaults
    if path is None:
        dir = sess.c.homedir
        name = owner
    else:
        dir = path[:-1]
        name = path[-1]
    if (mode==EXCLUSIVE4) and (verifier==None):
        verifier = sess.c.verifier
    if not want_deleg and access & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK == 0:
        access |= OPEN4_SHARE_ACCESS_WANT_NO_DELEG
    # Create the file
    open_op = op.open(0, access, deny, open_owner4(0, owner),
                      openflag4(OPEN4_CREATE, createhow4(mode, attrs, verifier)),
                      open_claim4(CLAIM_NULL, name))
    return sess.compound(use_obj(dir) + [open_op, op.getfh()])

def create_confirm(sess, owner, path=None, attrs={FATTR4_MODE: 0o644},
                   access=OPEN4_SHARE_ACCESS_BOTH,
                   deny=OPEN4_SHARE_DENY_NONE,
                   mode=GUARDED4):
    """Create (using open) a regular file, and confirm the open

    Returns the fhandle and stateid from the confirm.
    """
    res = create_file(sess, owner, path, attrs, access, deny, mode)
    check(res, msg="Creating file %s" % _getname(owner, path))
    fh = res.resarray[-1].object
    openstateid = stateid4(0, res.resarray[-2].stateid.other)
    return fh, openstateid

def _getname(owner, path):
    if path is None:
        return owner
    else:
        return path[-1]

def close_file(sess, fh, stateid, seqid=0):
    """close the given file"""
    if fh is None:
        ops = []
    else:
        ops = [op.putfh(fh)]
    ops += [op.close(seqid, stateid)]
    res = sess.compound(ops)
    return res
