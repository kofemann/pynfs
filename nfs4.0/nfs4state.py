from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
import rpc.rpc
import nfs4acl
import nfs4lib
import os, time, array, random, string
try:
    import cStringIO.StringIO as StringIO
except:
    from io import StringIO
from stat import *
import sha


inodecount = 0
generationcount = 0

InstanceKey = string.join([random.choice(string.ascii_letters) for x in range(4)], "")
def Mutate():
    global InstanceKey
    InstanceKey = string.join([random.choice(string.ascii_letters) for x in range(4)], "")


POSIXLOCK = True # If True, allow locks to be split/joined automatically
POSIXACL = True # If True, forces acls to follow posix mapping rules

class NFS4Error(Exception):
    def __init__(self, code, msg=None, attrs=0, lock_denied=None):
        self.code = code
        self.name = nfsstat4[code]
        if msg is None:
            self.msg = "NFS4 error code: %s" % self.name
        else:
            self.msg = str(msg)
        self.attrs = attrs
        self.lock_denied = lock_denied

    def __str__(self):
        return self.msg

def mod32(number):
    # int(number%0x100000000) doesn't work, since int is signed, we only
    # have 31 bits to play with
    return number % 0x100000000

def converttime(now=None):
    """Return time in nfstime4 format"""
    if now is None:
        now = time.time()
    sec = int(now)
    nsec = (now-sec) * 1000000000
    return nfstime4(sec, nsec)

def packnumber(number, size=NFS4_VERIFIER_SIZE, factor=1):
    """Return a string of length size which holds bitpacked number

    If result will not fit, the high bits are truncated.
    """
    numb = long(number * factor)
    bytes = array.array('B')
    for i in range(size):
        bytes.append(0)
    # i == size - 1
    while numb > 0 and i >= 0:
        bytes[i] = numb % 256
        numb /= 256
        i -= 1
    return bytes.tostring()

def unpacknumber(str):
    """Return number associated with bitpacked string"""
    numb = 0
    for c in str:
        numb = 256 * numb + ord(c)
    return numb

def printverf(verifier):
    """Returns a printable version of a 'binary' string"""
    str = ""
    for c in verifier:
        str += "%x" % ord(c)
    return str

#########################################################################

class NFSServerState:
    """Holds server state info"""
    def __init__(self, root):
        self.next_id = 2 # 0 and 1 are reserved
        self.special_ids = [0, 1]
        self.confirmed = self.ClientIDCache()
        self.unconfirmed = self.ClientIDCache()
        self.clientenum = 0 # Used as part of clientid
        self.state = {} # form {id : StateIDInfo}
        self.instance = packnumber(time.time(), 4)
        self.write_verifier = packnumber(time.time())
        self.openowners = {} # form {clientid : {other : OwnerInfo} }
        self.lockowners = {} # form {clientid : {other : OwnerInfo} }
        self.rootfh = root # FIXME used to get leasetime, should be better way

    class ClientIDCache:
        def __init__(self):
            self.list = []
            self.dict = {}

        class CacheEntry:
            def __init__(self, v, x, c, k, s, p):
                self.v = v
                self.x = x
                self.c = c
                self.k = k
                self.s = s
                self.time = int(time.time())
                self.principal = p
            def __repr__(self):
                return "(%s, %s, %s, *, %s: %i)" % (printverf(self.v), self.x[:16], self.c, printverf(self.s), self.time)
            def matches(self, v=None, x=None, c=None, k=None, s=None):
                """Returns True if self matches input values given

                None matches everything
                """
                if v is not None and v != self.v: return False
                if x is not None and x != self.x: return False
                if c is not None and c != self.c: return False
                if k is not None and k != self.k: return False
                if s is not None and s != self.s: return False
                return True

        def add(self, v, x, c, k, s, p):
            """Add entry into cache

            v is verifier supplied by client (opaque[8])
            x is name supplied by client (opaque<1024>)
            c is server supplied clientid (unint64)
            k is callback info supplied by client
            s is server supplied verifier (opaque[8])
            p is principal
            """
            # This assumes does not already exist in cache
            entry = self.CacheEntry(v, x, c, k, s, p)
            if self.exists(x=x) or self.exists(c=c):
                raise "Bad Cache"
            self.list.append(entry)
            self.dict[c] = entry

        def addentry(self, entry):
            if not isinstance(entry, self.CacheEntry):
                raise TypeError("Bad entry: %s" % str(entry))
            if self.exists(x=entry.x) or self.exists(c=entry.c):
                raise "Bad Cache"
            self.list.append(entry)
            self.dict[entry.c] = entry

        def exists(self, v=None, x=None, c=None, k=None, s=None):
            """Returns True if cache contains an entry matching input"""
            for entry in self.list:
                if entry.matches(v, x, c, k, s): return True
            return False

        def remove(self, v=None, x=None, c=None, k=None, s=None):
            """Remove all cache entries matching input"""
            for i, entry in zip(range(len(self.list)), self.list):
                if entry.matches(v, x, c, k, s):
                    del self.list[i]
                    del self.dict[entry.c]

        def find(self, v=None, x=None, c=None, k=None, s=None):
            """Returns first cache entry matching input, or None"""
            for entry in self.list:
                if entry.matches(v, x, c, k, s): return entry
            return None

        def renew(self, client):
            """Renews lease for client"""
            self.dict[client].time = int(time.time())

        def expired(self, client, secs):
            """Returns True if client has not been renewed in past secs"""
            return int(time.time()) - self.dict[client].time > secs

    class StateIDInfo:
        """State associated with an id"""
        def __init__(self, fh, ownerinfo):
            self.fh = fh
            self.owner = ownerinfo
            self.seqid = 0
            self.id = None
            self.closed = False

        def __repr__(self):
            return "%s : %s : %i" % (self.fh.name, self.owner.owner, self.seqid)

    class OwnerInfo:
        """State associated with a single owner"""
        def __init__(self, owner, openid=None):
            """owner should be of type open_owner4 or lock_owner4"""
            if isinstance(owner, open_owner4):
                self.lockowners = [] # form [OwnerInfo, ...]
            elif isinstance(owner, lock_owner4):
                self.openid = openid
            else:
                raise TypeError("Passed in owner = %s" % str(owner))
            # An owner is confirmed with OpenConfirm, a lock by sending stateid
            self.confirmed = False
            self.owner = owner
            self.lastseqid = None
            self.cached_response = None
            self.files = {} # form {fh.handle : id}

        def __repr__(self):
            if isinstance(self.owner, lock_owner4):
                return "<LOCK - %s, seqid=%s, %i files locked, %s>" % \
                       (self.owner, self.lastseqid, len(self.files), self.confirmed)
            else:
                return "<OPEN - %s, seqid=%s, %i files open, %s>" % \
                       (self.owner, self.lastseqid, len(self.files), self.confirmed)

    def new_clientid(self):
        """Return a clientid not previously used by server"""
        self.clientenum += 1
        return unpacknumber(self.instance) * 0x100000000 + \
               mod32(self.clientenum)

    def reset_seqid(self, clientid):
        """Reinitialize the sequence history for all owners with clientid"""
        try:
            for owner in self.openowners[clientid].values():
                owner.lastseqid = None
        except KeyError:
            pass
        try:
            for owner in self.lockowners[clientid].values():
                owner.lastseqid = None
        except KeyError:
            pass

    def check_seqid(self, obj, seqid, mustexist=True, open_confirm=False):
        """Check that seqid against stored one for obj.

        obj is either a stateid or a owner/fh pair.
        If mustexist is False, we can return OK if owner not found.
        Caller should be prepared to handle return of cached response.
        See RFC 3530 sec 8.1.5
        """
        # This is getting too complicated.  Should split off creation
        #print("  check_seqid: Entered")
        if isinstance(obj, stateid4):
            mustexist = True
        try:
            info = self.__getinfo(obj, allownew=not mustexist)
        except ValueError as e:
            if mustexist: raise
        #print("  check_seqid: %s" % info)
        if info is None:
            # A reserved stateid
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        if info.lastseqid is None:
            # Newly created owner, set lastseqid
            if isinstance(info.owner, open_owner4):
                # An openowner can start anywhere, based on assumption that
                # server may have released state that client was still using.
                # (See RFC 3530 sec 8.1.8)
                info.lastseqid = mod32(seqid-1)
            return
        elif (not info.confirmed) and isinstance(info.owner, lock_owner4):
            info.lastseqid = mod32(-1)
            return
        lastseq = info.lastseqid
        #print("  check_seqid: new: %s, last: %s" % (seqid, lastseq))
        if lastseq == seqid:
            print(" ***REPLAY*** ")
            return info.cached_response
        if not info.confirmed and not open_confirm:
            # RFC 3530 sec 14.2.18
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        if mod32(lastseq + 1) == seqid:
            return
        raise NFS4Error(NFS4ERR_BAD_SEQID)

    def advance_seqid(self, owner, op, args, cfh=None):
        """Advance stored seqid for owner, if appropriate. Cache the rest.

        Note cfh must match with owner if owner is not a stateid.
        """
        # RFC 3530 sec 8.1.5
        try:
            info = self.__getinfo(owner)
        except (ValueError as NFS4Error):
            # An unknown owner, do nothing
            return
        if info is None:
            # A reserved stateid, do nothing
            # FIXME - does this behave correctly for reserved stateids?
            return
        info.cached_response = (cfh, args, op)
        #print("  advance_seqid - went from: %s" % info.lastseqid)
        if args[0] not in [NFS4ERR_STALE_CLIENTID, NFS4ERR_STALE_STATEID,
                           NFS4ERR_BAD_STATEID, NFS4ERR_BAD_SEQID,
                           NFS4ERR_BADXDR, NFS4ERR_RESOURCE,
                           NFS4ERR_NOFILEHANDLE]:
            if info.lastseqid is None:
                info.lastseqid = 0
            else:
                info.lastseqid = mod32(info.lastseqid + 1)
        #print("  advance_seqid -        to: %s" % info.lastseqid)

    def confirm(self, fh, stateid):
        """Confirm an open"""
        id = self.__state2id(stateid, True)
        if id in self.special_ids:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        info = self.state[id].owner
        if info.confirmed:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        else:
            info.confirmed = True
        return self.__stateid(id)

    def open(self, fh, owner, access, deny):
        """Add given shares, after checking for conflicts.

        Conflict will raise NFS4Error.
        """
        if not isinstance(owner, open_owner4):
            raise TypeError("Owner was given as %s" % str(owner))
        info = self.__getinfo(owner)
        if not info.confirmed:
            # Remove any pending open (RFC 3530 sec 14.2.18)
            if info.files:
                if len(info.files) != 1:
                    raise "There should only be one file in %s" % info
                if len(info.lockowners) != 0:
                    raise "There should be no locks yet for %s" % info
                id = info.files.values()[0]
                fh.state.downshares(id, 0, 0)
                info.files.clear()
                del self.state[id]
            flags = OPEN4_RESULT_CONFIRM
        else:
            flags = 0
        id = self.__owner2id(owner, fh, allownew=True)
        fh.state.addshares(id, access, deny)
        return (self.__stateid(id), flags)

    def close(self, stateid):
        """Remove state associated with stateid."""
        id = self.__state2id(stateid, True)
        if id in self.special_ids:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        if self.state[id].closed:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        info = self.state[id].owner
        fh = self.__getfh(id)
        #print("Close fh from id", fh.handle)
        # Remove locks from file and deal with associated lockowners
        for lockinfo in info.lockowners:
            if fh.handle in lockinfo.files:
                lockid = lockinfo.files[fh.handle]
                fh.state.removelocks(lockid)
                del lockinfo.files[fh.handle]
                del self.state[lockid]
                lockinfo.confirmed = False
                info.lockowners.remove(lockinfo)
        # Remove share information
        fh.state.downshares(id, 0, 0)
        # Remove fh-id from openowner
        del info.files[fh.handle]
        # Flag advance_seqid to remove id from state
        self.state[id].closed = True
        self.__renew(id)

    def __stateid(self, id):
        """Return a nfs4 stateid4 for the given id, and renew lease"""
        self.__renew(id)
        other = self.instance + packnumber(id)
        self.state[id].seqid = mod32(self.state[id].seqid + 1)
        return stateid4(self.state[id].seqid, other)

    def __state2id(self, stateid, checkseq=False):
        """Translate nfs4 stateid to internal id"""
        if not isinstance(stateid, stateid4):
            raise TypeError("State was given as %s" % str(stateid))
        # Check for special stateids
        if stateid.seqid==0 and stateid.other==chr(0)*12:
            return 0
        if stateid.seqid==0xffffffff and stateid.other==chr(0xff)*12:
            return 1
        # Check for self consistency
        if stateid.other[:4] != self.instance:
            raise NFS4Error(NFS4ERR_STALE_STATEID)
        id = unpacknumber(stateid.other[-8:])
        if id not in self.state:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        if checkseq and stateid.seqid != self.state[id].seqid:
            if stateid.seqid < self.state[id].seqid:
                raise NFS4Error(NFS4ERR_OLD_STATEID)
            else:
                raise NFS4Error(NFS4ERR_BAD_STATEID)
        return id

    def __owner2id(self, owner, fh, allownew=False):
        """Returns id for given owner/fh pair.

        If allownew is True, will create a new id for the pair if none exists
        """
        info = self.__owner2info(owner, allownew)
        try:
            if fh is None:
                raise ValueError("File is None")
            return info.files[fh.handle]
        except KeyError:
            if not allownew:
                raise ValueError("File %s not open for %s" % (fh.name, info))
            #print("Creating new id %i for fh %s" % (self.next_id, fh.handle))
            id = info.files[fh.handle] = self.next_id
            self.next_id += 1
            self.state[id] = self.StateIDInfo(fh, info)
            return id

    def __owner2info(self, owner, allownew=False):
        """Returns info for given owner.

        If allownew is True, will create a new info if none exists for owner
        """
        if isinstance(owner,  open_owner4):
            ownerdict = self.openowners
        elif isinstance(owner, lock_owner4):
            ownerdict = self.lockowners
        else:
            raise TypeError("Gave owner as %s" % str(owner))
        self.__check_clientid(owner.clientid)
        try:
            info = ownerdict[owner.clientid][owner.owner]
        except KeyError:
            if not allownew: raise ValueError("Unknown owner %s" % str(owner))
            #print("Creating new info")
            info = self.OwnerInfo(owner)
            if owner.clientid in ownerdict:
                ownerdict[owner.clientid][owner.owner] = info
            else:
                ownerdict[owner.clientid] = {owner.owner : info}
        return info

    def __getid(self, obj, fh=None, checkseq=False, allownew=False):
        """Get ownerinfo related to obj, which may be of various types"""
        if isinstance(obj, stateid4):
            return self.__state2id(obj, checkseq=checkseq)
        else:
            return self.__owner2id(obj, fh, allownew=allownew)

    def __getinfo(self, obj, allownew=False):
        """Get OwnerInfo associated with obj.

        Returns None if obj is a special stateid.
        """
        if isinstance(obj, stateid4):
            id = self.__state2id(obj)
            if id in self.special_ids:
                return None
            else:
                info = self.state[id].owner
                if self.state[id].closed:
                    # FIXME Only check_seqid should get this back, otherwise
                    # an error.  'del' should happen in leasetime
                    # garbage collection
                    pass
                    #del self.state[id]
                return info
        else:
            return self.__owner2info(obj, allownew)

    def __getfh(self, id):
        """Returns fh associated with given id"""
        return self.state[id].fh

    def __getowner(self, id):
        """Returns owner associated with given id"""
        return self.state[id].owner.owner

    def __check_clientid(self, clientid):
        """Checks that clientid is not stale"""
        if clientid / 0x100000000 != unpacknumber(self.instance):
            raise NFS4Error(NFS4ERR_STALE_CLIENTID)

    def __renew(self, id):
        """Updates time on lease for clientid associated with id

        This is for implicit renews done by operations other than RENEW
        """
        if id not in self.special_ids:
            self.confirmed.renew(self.state[id].owner.owner.clientid)

    def renew(self, clientid):
        """Implements state changes of RENEW operation"""
        self.__check_clientid(clientid)
        try:
            self.confirmed.renew(clientid)
        except KeyError:
            raise NFS4Error(NFS4ERR_EXPIRED)

    def new_lockowner(self, openowner):
        """Use openowner data to create a new lock owner"""
        if openowner.lock_seqid != 0:
            raise NFS4Error(NFS4ERR_BAD_SEQID)
        openid = self.__state2id(openowner.open_stateid)
        clientid = self.__getowner(openid).clientid
        self.__check_clientid(clientid)
        self.__check_clientid(openowner.lock_owner.clientid)
        if clientid != openowner.lock_owner.clientid:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        info = self.__owner2info(openowner.lock_owner, allownew=True)
        # The lockowner must not already be locking a file.
        if info.confirmed:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
        if info.openid is not None:
            try:
                self.state[info.openid].owner.lockowners.remove(info)
            except ValueError:
                pass
        info.lastseqid = None
        info.cached_response = None
        info.files = {}
        info.openid = openid
        self.state[openid].owner.lockowners.append(info)
        return info

    def __getlockend(self, offset, length):
        if length == 0:
            raise NFS4Error(NFS4ERR_INVAL)
        if length == 0xffffffffffffffff:
            end = length
        else:
            end = length + offset
            if end > 0xffffffffffffffff:
                raise NFS4Error(NFS4ERR_INVAL)
            end -= 1
        return end

    def __expire(self, id):
        """Checks if lease is up, and if so returns True after removing state.

        Otherwise returns False
        """
        cid = self.state[id].owner.owner.clientid
        if self.confirmed.expired(cid, self.rootfh.fattr4_lease_time):
            self.remove_state(cid)
            return True
        else:
            return False


    def __testlock(self, fh, ids, type, offset, end):
        """Raise NFS4ERR_DENIED if conflicting lock exists"""
        deny = fh.state.testlock(ids, type, offset, end)
        if deny is not None:
            if self.__expire(deny[0]):
                return
            if deny[1].end == 0xffffffffffffffff:
                dlength = 0xffffffffffffffff
            else:
                dlength = deny[1].end + 1 - deny[1].start
            lock_denied = LOCK4denied(deny[1].start, dlength, deny[1].type,
                                      self.__getowner(deny[0]))
            raise NFS4Error(NFS4ERR_DENIED, lock_denied=lock_denied)

    def lock(self, fh, obj, type, offset, length):
        id = self.__getid(obj, fh, checkseq=True, allownew=True)
        # FIXME - check fh matches one associated with id
        end = self.__getlockend(offset, length)
        self.__testlock(fh, [id], type, offset, end)
        fh.state.addlock(id, type, offset, end)
        self.state[id].owner.confirmed = True
        return self.__stateid(id)

    def testlock(self, fh, owner, type, offset, length):
        self.__check_clientid(owner.clientid)
        if owner.clientid not in self.openowners and \
           owner.clientid not in self.lockowners :
            raise NFS4Error(NFS4ERR_STALE_CLIENTID)
        # FIXME - should a phantom testowner be created "for real" ?
        id = self.__owner2id(owner, fh, allownew=True)
        end = self.__getlockend(offset, length)
        self.__testlock(fh, [id], type, offset, end)

    def unlock(self, fh,  stateid, type, offset, length):
        id = self.__state2id(stateid, True)
        end = self.__getlockend(offset, length)
        fh.state.unlock(id, type, offset, end)
        return self.__stateid(id)

    def check_read(self, fh, stateid, offset, length):
        """Raise an error if can not read from file area"""
        openid = id = self.__state2id(stateid, True)
        # If this is a lock stateid, switch to open stateid
        try:
            if id not in self.special_ids:
                openid = self.state[id].owner.openid
        except AttributeError:
            pass
        self.__renew(id)
        # FIXME - deal with reserved stateids
        fh.state.checkaccess(openid, OPEN4_SHARE_ACCESS_READ)
        if length == 0: return
        end = self.__getlockend(offset, length)
        if id not in self.special_ids:
            if openid != id:
                # It was a lock stateid, easy
                ids = [id]
            else:
                # It was an open stateid, must check all corresponding locks
                ids = self.__locklist(openid)
            self.__testlock(fh, ids, READ_LT, offset, end)

    def check_write(self, fh, stateid, offset, length):
        """Raise an error if can not write to file area"""
        openid = id = self.__state2id(stateid, True)
        # If this is a lock stateid, switch to open stateid
        try:
            if id not in self.special_ids:
                openid = self.state[id].owner.openid
        except AttributeError:
            pass
        self.__renew(id)
        # FIXME - deal with reserved stateids
        fh.state.checkaccess(openid, OPEN4_SHARE_ACCESS_WRITE)
        if length == 0: return
        end = self.__getlockend(offset, length)
        if id not in self.special_ids:
            if openid != id:
                # It was a lock stateid, easy
                ids = [id]
            else:
                # It was an open stateid, must check all corresponding locks
                ids = self.__locklist(openid)
            self.__testlock(fh, ids, WRITE_LT, offset, end)

    def __locklist(self, id):
        """Given an open id, find all lock ids associated with it"""
        fh = self.state[id].fh.handle
        owner = self.state[id].owner
        list = []
        for lockowner in owner.lockowners:
            if lockowner.openid == id:
                list.append(lockowner.files[fh])
        return list

    def downgrade(self, fh, stateid, access, deny):
        """Downgrade to given shares, raise error if appropriate"""
        if access & 3 == 0:
            raise NFS4Error(NFS4ERR_INVAL)
        id = self.__state2id(stateid, True)
        fh.state.downshares(id, access, deny)
        return self.__stateid(id)

    def remove_state(self, clientid):
        """Remove all state associated with clientid"""
        # Remove lockowners and their locks
        if clientid in self.lockowners:
            for info in self.lockowners[clientid].values():
                if len(info.files) > 1:
                    raise "Too many files in %s" % str(info)
                for id in info.files.values():
                    # Unlock file
                    fh = self.state[id].fh
                    fh.state.removelocks(id)
                    del self.state[id]
            del self.lockowners[clientid]
        # Remove openowners and their share reservations
        if clientid in self.openowners:
            for info in self.openowners[clientid].values():
                for id in info.files.values():
                    # Remove shares
                    fh = self.state[id].fh
                    fh.state.downshares(id, 0, 0)
                    del self.state[id]
            del self.openowners[clientid]


#########################################################################


class NFSFileState:
    """Holds file state info"""
    def __init__(self):
        self.locks = {}  # form {id: [LockInfo, ...]}
        self.shares = {} # form {id : [3bit_access, 3bit_deny]}
        self.access = 0  # Use external 2-bit format
        self.deny = 0    # Use external 2-bit format

    class LockInfo:
        def __init__(self, type, start, end):
            self.type = type # bit 0:  0=WRITE 1=READ
            self.start = start
            self.end = end
            if start < 0 or end < start:
                raise ValueError("Bad values for start and end (%s, %s)" % \
                                  (start, end))

        def __repr__(self):
            if self.type & 1: str = "READ"
            else: str = "WRITE"
            return "%sLOCK: %i to %i" % (str, self.start, self.end)

        def __cmp__(self, other):
            if type(other) == type(5):
                other = self.LockInfo(0, other, self.end)
            if not isinstance(other, NFSFileState.LockInfo):
                return NotImplemented
            if self.start < other.start: return -1
            elif self.start > other.start: return 1
            elif self.end < other.end: return -1
            elif self.end > other.end: return 1
            else: return 0

        def overlaps(self, start, end):
            """Returns True if given range overlaps that of lock"""
            return start <= self.start <= end or \
                   self.start <= start <= self.end

    def __2to3(self, value):
        """Change 2 bit external value to 3 bit internal"""
        value &= 3
        if value: return 2 ** (value-1)
        else: return 0

    def __3to2(self, value):
        """Change 3 bit internal value to 2 bit external"""
        if value & 4: return 3
        else: return value & 3

    def downshares(self, id, access, deny):
        """Downgrade shares.  access == deny == 0 removes shares completely"""
        if id not in self.shares:
            if access != 0 or deny != 0:
                raise "Unknown id"
            else:
                return
        old_access = self.shares[id][0]
        old_deny = self.shares[id][1]
        new_access = self.__2to3(access)
        new_deny = self.__2to3(deny)
        if new_access & ~old_access or new_deny & ~old_deny:
            raise NFS4Error(NFS4ERR_INVAL)
        if access == 0 and deny != 0:
            raise "Invalid values"
        # Set new value for id
        if access == 0 and deny == 0:
            del self.shares[id]
        else:
            self.shares[id] = [new_access, new_deny]
        # Adjust files overall values
        new_access = new_deny = 0
        for i in self.shares:
            new_access |= self.shares[i][0]
            new_deny |= self.shares[i][1]
        self.access = self.__3to2(new_access)
        self.deny = self.__3to2(new_deny)

    def addshares(self, id, access, deny):
        """Add given shares, after checking for conflicts."""
        self.testshares(access, deny)
        self.access |= access
        self.deny |= deny
        if id not in self.shares:
            self.shares[id] = [0,0]
        self.shares[id][0] |= self.__2to3(access)
        self.shares[id][1] |= self.__2to3(deny)

    def testshares(self, access, deny):
        """Raises NFS4Error if proposed shares conflict with existing"""
        if access == 0:
            raise NFS4Error(NFS4ERR_INVAL)
        if access & self.deny or deny & self.access:
            raise NFS4Error(NFS4ERR_SHARE_DENIED)

    def checkaccess(self, id, mode):
        """Raise erropr if owner id cannot access file with mode"""
        if id not in [0,1]:
            try:
                if self.__3to2(self.shares[id][0]) & mode != mode:
                    raise NFS4Error(NFS4ERR_OPENMODE)
            except KeyError:
                raise NFS4Error(NFS4ERR_BAD_STATEID)
        if mode & self.deny:
            # Can get here if use reserved stateid
            raise NFS4Error(NFS4ERR_SHARE_DENIED)

    def removelocks(self, id):
        """Remove all locks for given id"""
        if id in self.locks:
            del self.locks[id]

    def addlock(self, id, type, start, end):
        """Add lock, assuming we have already tested for no conflicts"""
        if id not in self.locks:
            # Simple case of no previous lock by this owner
            self.locks[id] = [self.LockInfo(type, start, end)]
            return
        if POSIXLOCK:
            self.addposixlock(self.locks[id], type, start, end)
            return
        # Handle nonPOSIX locks
        for lock in self.locks[id]:
            if lock.overlaps(start, end):
                if lock.start==start and lock.end==end:
                    #Up/downgrade existing lock
                    lock.type = type
                    return
                else:
                    raise NFS4Error(NFS4ERR_LOCK_RANGE)
        self.locks[id].append(self.LockInfo(type, start, end))

    def testlock(self, ids, type, start, end):
        """See if lock conflicts with owners not in 'ids' list

        Returns info on the conflicting lock if found, None otherwise.
        """
        for owner in self.locks:
            if owner in ids: continue
            for lock in self.locks[owner]:
                if lock.overlaps(start, end) and (type&1==0 or lock.type&1==0):
                    return (owner, lock)
        return None

    def unlock(self, id, type, start, end):
        """Remove a lock"""
        if id not in self.locks:
            return
        if POSIXLOCK:
            self.removeposixlock(self.locks[id], type, start, end)
            return
        # Handle nonPOSIX locks
        for i,lock in zip(range(len(self.locks[id])), self.locks[id]):
            if lock.overlaps(start, end):
                if lock.start == start and lock.end == end:
                    del self.locks[id][i]
                    if len(self.locks[id]) == 0:
                        del self.locks[id]
                    return
                else:
                    raise NFS4Error(NFS4ERR_LOCK_RANGE)
        return

    def addposixlock(self, list, type, start, end):
        """Adds lock to list, splitting/merging existing locks as necessary"""
        self.__removerange(list, start, end)
        list.append(self.LockInfo(type, start, end))
        list.sort()
        # Merge adjacent locks
        for i in range(len(list) - 1, 0, -1):
            if list[i].start == list[i-1].end + 1 and \
               list[i].type == list[i-1].type:
                  list[i-1].end = list[i].end
                  del list[i]
        print(list)

    def removeposixlock(self, list, type, start, end):
        """Removes lock from sorted list, splitting existing locks as necessary
        """
        self.__removerange(list, start, end)
        list.sort()
        print(list)

    def __removerange(self, list, start, end):
        """Removes locks in given range, shrinking locks that half-overlap"""
        # If start is inside a lock, we split that lock in two
        for lock in list:
            if lock.start < start <= lock.end:
                list.append(self.LockInfo(lock.type, start, lock.end))
                lock.end = start - 1
                break
        # If end is inside a lock, we split that lock in two
        for lock in list:
            if lock.start <= end < lock.end:
                list.append(self.LockInfo(lock.type, lock.start, end))
                lock.start = end + 1
                break
        # Remove all locks inside given range
        for lock in list[:]:
            if lock.overlaps(start, end):
                list.remove(lock)

#########################################################################

class NFSFileHandle:
    # name = the external NFS4 name
    # file = the real, local file
    # parent = the parent directory, None if root.
    def __init__(self, name, parent):
        global InstanceKey
        # Note: name should be removed, since hardlinking makes it unknowable
        self.name = name
        self.handle = InstanceKey + self.get_fhclass() + sha.new(self.name+str(time.time())).hexdigest() + "\x00\x00\x00\x00"
        self.fattr4_change = 0
        self.lock_status = {}
        self.parent = parent

    def find(self, file):
        # search through the filesystem for a filename
        raise "implement find."

    def __repr__(self):
        return "<NFSFileHandle(%s): %s>" % (self.get_fhclass(), str(self))

    def __str__(self):
        return self.name

    def supported_access(self, client):
        raise "Implement supported_access()"

    def evaluate_access(self, client):
        raise "Implement evaluate_access()"

    def get_attributes(self, attrlist=None):
        raise "Implement get_attributes"

    def get_directory(self):
        raise "Implement get_directory"

    def get_type(self):
        raise "Implement get_type"

    def read(self, offset, count):
        raise "Implement read"

    def write(self, offset, data):
        raise "Implement write"

    def link(self, target):
        raise "Implement link"

    def destruct(self):
        raise "Implement destruct"

    def remove(self, target):
        raise "implement remove"


class VirtualHandle(NFSFileHandle):
    def __init__(self, name="/", type=None, parent=None):
        NFSFileHandle.__init__(self, name, parent)
        try:
            self.fattr4_type = type.type
        except AttributeError:
            if type is None: self.fattr4_type = NF4DIR
            else: raise
        self.st_uid = 0
        self.st_gid = 0
        self.named_attr = {}

        self._set_default_attrs()

        if self.fattr4_type == NF4DIR:
            self.dirent = DirList()
            self.fattr4_mode = 0o755
        if self.fattr4_type == NF4REG:
            self.file = StringIO.StringIO()
            self.state = NFSFileState()
        if self.fattr4_type == NF4LNK:
            self.link_target = type.linkdata
            self.link_filehandle = None
        if self.fattr4_type in [NF4BLK, NF4CHR]:
            self.fattr4_rawdev = type.devdata


    def _set_default_attrs(self):
        self.fattr4_supported_attrs = nfs4lib.list2bitmap([x for x in self.supported.keys() if not 'n' in self.supported[x]])
        self.fattr4_fh_expire_type = FH4_VOLATILE_ANY
        self.fattr4_change = 0
        self.fattr4_size = 0 # This is interpreted differently than in RFC
        self.fattr4_link_support = True
        self.fattr4_symlink_support = True
        self.fattr4_named_attr = False
        self.fattr4_fsid = fsid4(0x0, 0x0)
        self.fattr4_unique_handles = False
        self.fattr4_lease_time = 90 # Seconds
        self.fattr4_rdattr_error = NFS4_OK
        self.fattr4_filehandle = str(self.handle)
        self.fattr4_aclsupport = ACL4_SUPPORT_ALLOW_ACL | ACL4_SUPPORT_DENY_ACL
        self.fattr4_case_insensitive = False
        self.fattr4_case_preserving = True
        global inodecount
        inodecount += 1
        self.fattr4_fileid = inodecount
        self.fattr4_maxfilesize = 2**32  # Are these enforced?
        self.fattr4_maxname = 128 # Are these enforced?
        self.fattr4_maxread = 1000 # Are these enforced?
        self.fattr4_maxwrite = 1000 # Are these enforced?
        self.fattr4_mode = 0o644 # Currently no access restrictions enforced
        self.fattr4_acl = nfs4acl.mode2acl(self.fattr4_mode,
                                           self.fattr4_type == NF4DIR)
        self.fattr4_numlinks = 1 # Updated? - Yes
        self.fattr4_owner = "nobody@nowhere" # Stub
        self.fattr4_owner_group = "nobody@nowhere" # Stub
        self.fattr4_rawdev = specdata4(0,0)
        now = time.time()
        self.fattr4_time_access = converttime(now)
        self.fattr4_time_create = converttime(now)
        self.fattr4_time_modify = converttime(now) #Should modify imply access?
        self.fattr4_time_metadata = converttime(now)

    def match_create_verf(self, verf):
        """Return True if verf equals stored create_verf."""
        try:
            return self.create_verf == verf
        except AttributeError:
            return False

    def create(self, name, type, attrs={}):
        """ Create a file of given type with given attrs, return attrs set

        type is a nfs4types.createtype4 instance
        """
        # Must make sure that if it fails, nothing is changed
        if self.fattr4_type != NF4DIR:
            raise "create called on non-directory (%s)" % self.ref
        if self.dirent.has_name(name):
            raise "attempted to create already existing file."
        fh = VirtualHandle(name, type, self)
        if FATTR4_SIZE in attrs and type.type != NF4REG:
            del attrs[FATTR4_SIZE]
        if FATTR4_TIME_MODIFY_SET in attrs:
            del attrs[FATTR4_TIME_MODIFY_SET]
        if FATTR4_TIME_ACCESS_SET in attrs:
            del attrs[FATTR4_TIME_ACCESS_SET]
        self.fattr4_change += 1
        self.fattr4_time_metadata = converttime()
        attrset = fh.set_attributes(attrs)
        self.dirent[name] = fh
        self.fattr4_size = len(self.dirent)
        self.fattr4_time_modify = converttime()
        return attrset

    def evaluate_access(self):
        return self.supported_access()

    def supported_access(self):
        # page 140 lists that supported should be what the server can verify
        # reliably on the current_filehandle, so I suppose this should depend
        # on the file type
        if self.fattr4_type == NF4DIR:
            # according to page 142, UNIX does not aupport ACCESS4_DELETE on a file
            # however, we will.
            return ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE
#        elif self.fattr4_type == NF4REG:
            #
        else:
            return ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | ACCESS4_EXTEND | ACCESS4_DELETE | ACCESS4_EXECUTE

    # 'r' for read access, 'w' for write access, 'n' for not supported
    supported = { FATTR4_SUPPORTED_ATTRS : "r",
                  FATTR4_TYPE : "r",
                  FATTR4_FH_EXPIRE_TYPE : "r",
                  FATTR4_CHANGE : "r",
                  FATTR4_SIZE : "rw",
                  FATTR4_LINK_SUPPORT : "r",
                  FATTR4_SYMLINK_SUPPORT : "r",
                  FATTR4_NAMED_ATTR : "r",
                  FATTR4_FSID : "r",
                  FATTR4_UNIQUE_HANDLES : "r",
                  FATTR4_LEASE_TIME : "r",
                  FATTR4_RDATTR_ERROR : "r",
                  FATTR4_FILEHANDLE : "r",
                  FATTR4_ACL : "rw",
                  FATTR4_ACLSUPPORT : "r",
                  FATTR4_ARCHIVE : "rwn",
                  FATTR4_CANSETTIME : "rn",
                  FATTR4_CASE_INSENSITIVE : "r",
                  FATTR4_CASE_PRESERVING : "r",
                  FATTR4_CHOWN_RESTRICTED : "rn",
                  FATTR4_FILEID : "r",
                  FATTR4_FILES_AVAIL : "rn",
                  FATTR4_FILES_FREE : "rn",
                  FATTR4_FILES_TOTAL : "rn",
                  FATTR4_FS_LOCATIONS : "rn",
                  FATTR4_HIDDEN : "rwn",
                  FATTR4_HOMOGENEOUS : "rn",
                  FATTR4_MAXFILESIZE : "r",
                  FATTR4_MAXLINK : "rn",
                  FATTR4_MAXNAME : "r",
                  FATTR4_MAXREAD : "r",
                  FATTR4_MAXWRITE : "r",
                  FATTR4_MIMETYPE : "rwn",
                  FATTR4_MODE : "rw", # Not supported, but needed as stub
                  FATTR4_NO_TRUNC : "rn",
                  FATTR4_NUMLINKS : "r",
                  FATTR4_OWNER : "rw",
                  FATTR4_OWNER_GROUP : "rw",
                  FATTR4_QUOTA_AVAIL_HARD : "rn",
                  FATTR4_QUOTA_AVAIL_SOFT : "rn",
                  FATTR4_QUOTA_USED : "rn",
                  FATTR4_RAWDEV : "r",
                  FATTR4_SPACE_AVAIL : "rn",
                  FATTR4_SPACE_FREE : "rn",
                  FATTR4_SPACE_TOTAL : "rn",
                  FATTR4_SPACE_USED : "rn",
                  FATTR4_SYSTEM : "rwn",
                  FATTR4_TIME_ACCESS : "r",
                  FATTR4_TIME_ACCESS_SET : "w",
                  FATTR4_TIME_BACKUP : "rwn",
                  FATTR4_TIME_CREATE : "rw",
                  FATTR4_TIME_DELTA : "rn",
                  FATTR4_TIME_METADATA : "r",
                  FATTR4_TIME_MODIFY : "r",
                  FATTR4_TIME_MODIFY_SET : "w",
                  FATTR4_MOUNTED_ON_FILEID : "rn",
                  }

    def set_attributes(self, attrdict):
        """Set attributes and return bitmask of those set

        attrdict is of form {bitnum:value}
        For each bitnum, it will try to call self.set_fattr4_<name> if it
        exists, otherwise it will just set the variable self.fattr4_<name>.
        """
        mapping = nfs4lib.list2bitmap
        ret_list = []
        for attr in attrdict.keys():
            if not attr in self.supported:
                raise NFS4Error(NFS4ERR_ATTRNOTSUPP, attrs=mapping(ret_list))
            if 'w' not in self.supported[attr]:
                raise NFS4Error(NFS4ERR_INVAL, attrs=mapping(ret_list))
            if 'n' in self.supported[attr]:
                raise NFS4Error(NFS4ERR_ATTRNOTSUPP, attrs=mapping(ret_list))
            name = "fattr4_" + nfs4lib.get_attr_name(attr)
            self.fattr4_change += 1
            try:
                # Use set function, if it exists
                set_funct = getattr(self, "set_" + name)
                set_funct(attrdict[attr])
            except AttributeError:
                # Otherwise, just set the variable
                setattr(self, name, attrdict[attr])
            except NFS4Error as e:
                # Note attributes set so far in any error that occurred
                e.attrs = mapping(ret_list)
                raise
            self.fattr4_time_metadata = converttime()
            ret_list.append(attr)
        return mapping(ret_list)

    def set_fattr4_size(self, newsize):
        # FRED - How should this behave on non REG files? especially a DIR?
        if self.fattr4_type == NF4REG and newsize != self.fattr4_size:
            if newsize < self.fattr4_size:
                self.file.truncate(newsize)
            else:
                # Pad with zeroes
                self.file.seek(0, 2)
                self.file.write(chr(0) * (newsize-self.fattr4_size))
            self.fattr4_size = newsize
            self.fattr4_time_modify = converttime()
        else:
            raise NFS4Error(NFS4ERR_INVAL)

    def set_fattr4_time_modify_set(self, new_time):
        if new_time.set_it == SET_TO_CLIENT_TIME4:
            self.fattr4_time_modify = new_time.time
        else:
            self.fattr4_time_modify = converttime()

    def set_fattr4_time_access_set(self, new_time):
        if new_time.set_it == SET_TO_CLIENT_TIME4:
            self.fattr4_time_access = new_time.time
        else:
            self.fattr4_time_access = converttime()

    def set_fattr4_acl(self, acl):
        if POSIXACL:
            try:
                nfs4acl.maps_to_posix(acl)
            except nfs4acl.ACLError as e:
                print("*"*50)
                print(e)
                print("*"*50)
                raise NFS4Error(NFS4ERR_INVAL)
        self.fattr4_acl = acl
        self.fattr4_mode = nfs4acl.acl2mode(acl)

    def get_attributes(self, attrlist=None, ignore=True):
        """Given a list of bit numbers, return a dict of {bitnum:attr}"""
        # Make sure any error is recorded in fattr4_rdattr_error
        ret_dict = {}
        for attr in attrlist:
            if not attr in self.supported:
                # Ignore unknown attributes
                continue
            if 'r' not in self.supported[attr]:
                # self.fattr4_rdattr_error = NFS4ERR_INVAL
                # raise NFS4Error(NFS4ERR_INVAL)
                continue
            if 'n' in self.supported[attr]:
                if ignore:
                    # Ignore unsupported attributes
                    continue
                else:
                    raise NFS4Error(NFS4ERR_ATTRNOTSUPP)
            name = "fattr4_" + nfs4lib.get_attr_name(attr)
            try:
                # Use get function, if it exists
                get_funct = getattr(self, "get_" + name)
                ret_dict[attr] = get_funct()
            except AttributeError:
                # Otherwise, just get the variable
                ret_dict[attr] = getattr(self, name)
        self.fattr4_rdattr_error = NFS4_OK
        return ret_dict

    def hardlink(self, file, newname):
        # FRED - how deal with name? parent?
        #        answer - a file cannot know its own name
        #               - a dir cannot be hardlinked
        if self.fattr4_type != NF4DIR:
            raise "hardlink called with non-directory self"
        if file.fattr4_type == NF4DIR:
            raise "hardlink to a directory"

        self.__link(file, newname)

    def __link(self, file, newname):
        if self.fattr4_type != NF4DIR:
             raise "__link called on non-directory"
        file.fattr4_change += 1
        file.fattr4_numlinks += 1
        file.fattr4_time_metadata = converttime()
        if file.fattr4_type == NF4DIR:
            file.parent = self
        self.fattr4_change += 1
        self.dirent[newname] = file
        self.fattr4_size = len(self.dirent)
        self.fattr4_time_modify = converttime()
        self.fattr4_time_metadata = converttime()
        return

    def get_fhclass(self):
        return "virt"

    def get_type(self):
        return self.fattr4_type

    def is_empty(self):
        """For a directory, return True if empty, False otherwise"""
        if self.fattr4_type == NF4DIR:
            return len(self.dirent) == 0
        raise "is_empty() called on non-dir"

    def read(self, offset, count):
        if self.fattr4_type != NF4REG:
            raise "read called on non file!"
        self.file.seek(offset)
        data = self.file.read(count)
        self.fattr4_time_access = converttime()
        return data

    def destruct(self):
        # FRED - Note this currently does nothing -
        #      - and should do nothing if link count is positive
        if self.fattr4_numlinks > 0: return
        #print("destructing: %s" % repr(self))
        if self.fattr4_type == NF4DIR:
            for subfile in self.dirent.values():
                subfile.destruct()

    def remove(self, target):
        self.fattr4_change += 1
        file = self.dirent[target]
        del self.dirent[target]
        file.fattr4_numlinks -= 1
        file.fattr4_change += 1
        file.fattr4_time_metadata = converttime()
        file.destruct()
        self.fattr4_size = len(self.dirent)
        self.fattr4_time_modify = converttime()
        self.fattr4_time_metadata = converttime()

    def rename(self, oldfh, oldname, newname): # self = newfh
        file = oldfh.dirent[oldname]
        self.__link(file, newname)
        oldfh.remove(oldname)

    def read_dir(self, cookie=0):
        if self.fattr4_type == NF4DIR:
            self.fattr4_time_access = converttime()
            return self.dirent.readdir(cookie)
        else:
            raise "read_dir called on non directory."

    def getdirverf(self):
        if self.fattr4_type == NF4DIR:
            self.fattr4_time_access = converttime()
            return self.dirent.verifier
        else:
            raise "getdirverf called on non directory."

    def read_link(self):
        if self.fattr4_type != NF4LNK:
            raise "read_link called on non NF4LNK."
        else:
            return self.link_target

    def lookup(self, name):
        """ Assume we are a dir, and see if name is one of our files.

        If yes, return it.  If no, return None
        """
        if self.fattr4_type != NF4DIR:
            raise "lookup called on non directory."
        try: return self.dirent[name]
        except KeyError: return None

    def do_lookupp(self):
        """Return parent dir, or None for root"""
        # Note because of hardlinks, parent only makes sense for
        #   directories, which can not be hardlinked
        if self.fattr4_type != NF4DIR:
            raise "lookupp called on non directory."
        return self.parent

    def write(self, offset, data):
        if self.fattr4_type != NF4REG:
            raise "write called on non file!"
        if len(data) == 0: return 0
        self.fattr4_change += 1
        try: self.file.seek(offset)
        except MemoryError:
            print("MemError, offset=%s, count=%s" % (str(offset), str(len(data))))
            raise
        self.file.write(data)
        self.file.seek(0, 2) # Seek to eof
        self.fattr4_size = self.file.tell()
        self.fattr4_time_modify = converttime()
        self.fattr4_time_metadata = converttime()
        return len(data)

class HardHandle(NFSFileHandle):
    def __init__(self, filesystem, name, parent, file):
        NFSFileHandle.__init__(self, name, parent)
        self.file = file
        self.dirent = None
        self.mtime = 0

    def do_lookupp(self):
        return self.parent

    def get_attributes(self, attrlist=None):
        stat_struct = os.lstat(self.file)
        ret_dict = {};
        for attr in attrlist:
            if attr == FATTR4_TYPE:
                if S_ISDIR(stat_struct.st_mode):
                   ret_dict[attr] = NF4DIR
                elif S_ISREG(stat_struct.st_mode):
                    ret_dict[attr] = NF4REG
                elif S_ISLNK(stat_struct.st_mode):
                    ret_dict[attr] = NF4LNK
            elif attr == FATTR4_CHANGE:
                        ret_dict[attr] = nfstime4(stat_struct.st_ctime, 0);
            elif attr == FATTR4_SIZE:
                    ret_dict[attr] = stat_struct.st_size
            elif attr == FATTR4_FSID:
                    ret_dict[attr] = fsid4(0, 0)
            elif attr == FATTR4_LEASE_TIME:
                    ret_dict[attr] = 1700
            elif attr == FATTR4_FILEID:
                    ret_dict[attr] = stat_struct.st_ino
            elif attr == FATTR4_MAXFILESIZE:
                    ret_dict[attr] = 1000000
            elif attr == FATTR4_MAXREAD:
                    ret_dict[attr] = 1000
            elif attr == FATTR4_MAXWRITE:
                    ret_dict[attr] = 1000
            elif attr == FATTR4_MODE:
                    ret_dict[attr] = stat_struct.st_mode
            elif attr == FATTR4_NUMLINKS:
                    ret_dict[attr] = stat_struct.st_nlink
            elif attr == FATTR4_OWNER:
                    ret_dict[attr] = stat_struct.st_uid
            elif attr == FATTR4_OWNER_GROUP:
                    ret_dict[attr] = stat_struct.st_gid
            elif attr == FATTR4_RAWDEV:
                    ret_dict[attr] = specdata4(0, 0)
            elif attr == FATTR4_TIME_ACCESS:
                    ret_dict[attr] = nfstime4(stat_struct.st_atime, 0);
            elif attr == FATTR4_TIME_MODIFY:
                    ret_dict[attr] = nfstime4(stat_struct.st_mtime, 0);
        return ret_dict

    def get_fhclass(self):
        return "hard"

        def get_link(self):
                return os.readlink(self.file)

    def get_type(self):
        stat_struct = os.lstat(self.file)
        if S_ISDIR(stat_struct.st_mode):
            return NF4DIR
        elif S_ISREG(stat_struct.st_mode):
            return NF4REG
        elif S_ISLNK(stat_struct.st_mode):
            return NF4LNK
        else:
            return NF4REG

    def read(self, offset, count):
        fh = open(self.file)
        fh.seek(offset)
        data = fh.read(count)
        fh.close()
        return data


    def read_dir(self):
        stat_struct = os.stat(self.file)
        if not S_ISDIR(stat_struct.st_mode):
            raise "Not a directory."
        if stat_struct[ST_MTIME] == self.mtime:
            return self.dirent.values()
        self.oldfiles = self.dirent.keys()
        for i in os.listdir(self.file):
            fullfile = os.path.join(self.file, i)
            if not self.dirent.has_name(i):
                self.dirent[i] = HardHandle(i, self, fullfile)
            else:
                self.oldfiles.remove(i)
        for i in self.oldfiles:
            del self.dirent[i]
        return self.dirent.values()

    def read_link(self):
        return os.readlink(self.file)

    def write(self, offset, data):
        fh = open(self.file, 'r+')
        fh.seek(offset)
        fh.write(data)
        fh.close()
        return len(data)

# This seems to be only used now by O_Readdir...can we get rid of it?
## class NFSClientHandle:
##     def __init__(self):
##         self.confirmed = 0
##         self.dirlist = {}
##         self.iterlist = {}
##         self.verfnum = 0
##         self.lock_owner = None
##         self.clientid = None

##     def confirm(self):
##         self.confirmed = 1

##     def nextverf(self):
##         """Return a verifier not previously seen by client"""
##         self.verfnum += 1
##         return packnumber(self.verfnum)

#####################################################################

class DirList:
    def __init__(self):
        self.verifier = packnumber(int(time.time()))
        self.list = []
        self.__lastcookie = 2

    class DirEnt:
        def __init__(self, name, fh, cookie):
            self.name = name
            self.fh = fh
            self.cookie = cookie

    def __len__(self):
        return len(self.list)

    def __getitem__(self, name):
        """Allows  fh = self[name]"""
        for x in self.list:
            if x.name == name:
                return x.fh
        raise KeyError("Invalid key %s" % name)

    def __setitem__(self, name, fh):
        """Allows self[name] = fh"""
        # Remove if already in list
        for x in self.list:
            if x.name == name:
                del self.list[x]
        # Append to end of list
        self.list.append(self.DirEnt(name, fh, self.__nextcookie()))

    def __nextcookie(self):
        self.__lastcookie += 1
        return self.__lastcookie

    def __delitem__(self, name):
        """Allows del self[name]"""
        for x in self.list:
            if x.name == name:
                self.list.remove(x)
                return
        raise KeyError("Invalid key %s" % name)

    def getcookie(self, name):
        for x in self.list:
            if x.name == name:
                return x.cookie
        raise KeyError("Invalid key %s" % name)

    def readdir(self, cookie):
        """Returns DirEnt list containing all entries larger than cookie"""
        if cookie < 0 or cookie > self.__lastcookie:
            raise IndexError("Invalid cookie %i" % cookie)
        i = None
        for x in self.list:
            if x.cookie > cookie:
                i = self.list.index(x)
                break
        if i is None:
            return []
        else:
            return self.list[i:]

    def has_name(self, name):
        for x in self.list:
            if x.name == name:
                return True
        return False

    def keys(self):
        return [x.name for x in self.list]

    def values(self):
        return [x.fh for x in self.list]
