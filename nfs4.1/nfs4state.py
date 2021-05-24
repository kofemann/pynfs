from __future__ import with_statement
from contextlib import contextmanager
import threading
from locking import Lock
import struct
import nfs4lib
from nfs4lib import NFS4Error
#from xdrdef.nfs4_type import stateid4
from xdrdef.nfs4_type import *
from xdrdef.nfs4_const import *
import nfs_ops
import rpc.rpc as rpc
import logging

log = logging.getLogger("nfs.server.state")

op4 = nfs_ops.NFS4ops()

POSIXLOCK = False

SHARE, BYTE, DELEG, LAYOUT, ANON = range(5) # State types
NORMAL, CB_INIT, CB_SENT, CB_RECEIVED, INVALID = range(5) # delegation/layout states

DS_MAGIC = "\xa5" # STUB part of HACK code to ignore DS stateid

@contextmanager
def find_state(env, stateid, allow_0=True, allow_bypass=False):
    """Find the matching StateTableEntry, and manage its lock."""
    anon = False
    if env.is_ds:
        # STUB - have dataservers ignore stateid (but still do needed locking
        stateid = stateid4(0, DS_MAGIC * 12)
        state = env.cfh.state.types[ANON][(DS_MAGIC, )]
        # Could meddle with state.other here if needed
        anon = True
    # First we convert special stateids, see draft22 8.2.3
    if stateid.other == "\0" * 12:
        if allow_0 and stateid.seqid == 0:
            state = env.cfh.state.anon0
            anon = True
        elif stateid.seqid == 1:
            stateid = env.cid
            # Special stateids must be passed in explicitly
            if stateid in [None, nfs4lib.state00, nfs4lib.state11]:
                raise NFS4Error(NFS4ERR_BAD_STATEID,
                                tag="Current stateid not useable")
        else:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
    elif stateid.other == "\xff" * 12:
        if allow_0 and stateid.seqid == 0xffffffff:
            stateid = nfs4lib.state00 # Needed to pass seqid checks below
            state = (env.cfh.state.anon1 if allow_bypass else env.cfh.state.anon0)
            anon = True
        else:
            raise NFS4Error(NFS4ERR_BAD_STATEID)
    if not anon:
        # Now map stateid to find state
        state = env.session.client.state.get(stateid.other, None)
        if state is None:
            raise NFS4Error(NFS4ERR_BAD_STATEID, tag="stateid not known")
        if state.file != env.cfh:
            raise NFS4Error(NFS4ERR_BAD_STATEID,
                            tag="cfh %r does not match stateid %r" %
                            (state.file.fh, env.cfh.fh))
    state.lock.acquire()
    # It is possible that while waiting to get the lock, the state has been
    # removed.  In that case, the removal sets the invalid flag.
    if state.invalid:
        state.release()
        raise NFS4Error(NFS4ERR_BAD_STATEID, tag="stateid not known (race)")
    if state.type != LAYOUT:
        # See draft22 8.2.2
        if stateid.seqid != 0 and stateid.seqid != state.seqid:
            old = (stateid.seqid < state.seqid)
            state.lock.release()
            if old:
                raise NFS4Error(NFS4ERR_OLD_STATEID, tag="bad stateid.seqid")
            else:
                raise NFS4Error(NFS4ERR_BAD_STATEID, tag="bad stateid.seqid")
    else:
        # See draft22 12.5.3
        if stateid.seqid == 0:
            state.lock.release()
            raise NFS4Error(NFS4ERR_BAD_STATEID, tag="layout stateid.seqid==0")
    try:
        yield state
    finally:
        state.lock.release()

class ByteLock(object):
    """Holds a lock range and some simple methods for comparing."""

    iswrite = property(lambda s: s.type & 1 == 0)
    expired = False # STUB - this shouldn't even be here - needs to be
                    # determined at client level - just used as reminder to fix

    def __init__(self, type, start, end):
        self.type = type # bit 0:  0=WRITE 1=READ
        self.start = start
        self.end = end
        if start < 0 or end < start:
            raise ValueError("Bad values for start and end (%s, %s)" % \
                              (start, end))

    def __repr__(self):
        str = ("WRITE" if self.iswrite else "READ")
        return "%sLOCK: %i to %i" % (str, self.start, self.end)

    def __cmp__(self, other):
        out = cmp(self.start, other.start)
        if out == 0:
            return cmp(self.end, other.end)
        else:
            return out

    def overlaps(self, start, end, exact=False):
        """Returns True if given range overlaps that of lock.

        If exact==True, an overlap that does not match the lock range
        exactly raises an error.
        """
        out = start <= self.start <= end or \
              self.start <= start <= self.end
        if out and exact:
            if self.start != start or self.end != end:
                raise NFS4Error(NFS4ERR_LOCK_RANGE)
        return out

    def conflicts(self, other):
        """Returns True if given locks conflict."""
        return (self.iswrite or other.iswrite) and \
            self.overlaps(other.start, other.end)


class DictTree(object):
    """Holds StateTableEntries (which correspond to stateids).

    They are held as leaves of a tree of dictionaries, and are referenced
    by a key that is a tuple coresponding to the branch.  A None entry
    in the tuple refers to the whole subtree, when that makes sense.
    """
    def __init__(self, depth):
        self._data = {}
        self._depth = depth # Note must have depth >= 1

    def __nonzero__(self):
        """Is any state being held?"""
        return bool(self._data)

    def __getitem__(self, key):
        if len(key) != self._depth:
            raise KeyError("Wrong key length %i" % len(key))
        d = self._data
        for k in key:
            d = d[k]
        return d

    def hasbranch(self, key):
        """Returns True if branch exists"""
        if len(key) != self._depth:
            raise KeyError("Wrong key length %i" % len(key))
        d = self._data
        if key[0] is None:
            return self.__nonzero__()
        for k in key:
            if k is None:
                return True
            d = d.get(k)
            if d is None:
                return False
        return True

    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def __setitem__(self, key, value):
        """key is a tuple, add value to a tree of dicts"""
        if len(key) != self._depth:
            raise KeyError("Wrong key length %i" % len(key))
        d = self._data
        for k in key[:-1]:
            new_d = d.get(k, None)
            if new_d is None:
                new_d = d[k] = {}
            d = new_d
        d[key[-1]] = value

    def __delitem__(self, key):
        if len(key) != self._depth:
            raise KeyError("Wrong key length %i" % len(key))
        if key[0] is None:
            # Special case wiping everything
            self._data = {}
            return
        d = self._data
        # Determine the branch we want to prune
        branch = []
        for k in key:
            if k is None:
                break
            sub_d = d.get(k)
            if sub_d is None:
                raise KeyError("bad key %r" % (key,))
            branch.append((d, k))
            d = sub_d
        # Prune the branch
        for d, k in reversed(branch):
            del d[k]
            if d:
                return

    def itervalues(self):
        def myiter(d, depth):
            if depth == 1:
                for value in d.itervalues():
                    yield value
            else:
                for sub_d in d.itervalues():
                    for i in myiter(sub_d, depth - 1):
                        yield i
        for i in myiter(self._data, self._depth):
            yield i


class FileStateTyped(object):
    """Super of a class to holds all state of a single type for a single file.

    NOTE is is assumed that the lock is held pretty much the entire time
    the structure is in use.
    """
    def __init__(self, file, lock, depth):
        self.file = file
        self.lock = lock # Shared lock from FileState, passed to leaves
        self._tree = DictTree(depth)

    def itervalues(self):
        return self._tree.itervalues()

    def __getitem__(self, key):
        return self._tree[key]

    def get_new_other(self, client):
        """Create unique (per client) reference which will map to a stateid.

        Assumes lock is held
        """
        # NOTE we are only using 9 bytes of 12
        # NOTE this needs to be client-wide, since keys of client.state[]
        # must be unique
        return "%s%s" % (struct.pack("!xxxB", self.type),
                         client.get_new_other())

    def grab_entry(self, key, klass):
        """Returns tree[key] if it exists, otherwise creates it."""
        if key == (DS_MAGIC,):
            return self.file.state.types[ANON][(DS_MAGIC, )]
        entry = self._tree.get(key)
        if entry is None:
            client = key[0]
            other = self.get_new_other(client)
            entry = klass(other, self, key)
            self._tree[key] = entry
            client.state[other] = entry
        return entry

class DelegState(FileStateTyped):
    """Holds delegation state for a single file

    Note that there are either an arbitrary number of READ delegations,
    or a single WRITE delegation.
    """
    type = DELEG

    def __init__(self, *args, **kwargs):
        kwargs["depth"] = 1 # key = (client,)
        FileStateTyped.__init__(self, *args, **kwargs)
        # NOTE all delegations must be the same, either READ or WRITE.
        # Also note, there can only be one WRITE delegation out.

    def conflicts(self, client, access, deny):
        """Returns True if the given share values conflict with a delegation"""
        # NOTE - OK to have extra acess/deny flags
        if not self._tree:
            return False
        if deny & OPEN4_SHARE_DENY_READ:
            # DENY_READ conflicts with all delegations
            return True
        # Find any delegation - use fact that all are of same type
        for e in self._tree.itervalues():
            break
        # The only thing that doesn't conflict is access==READ with READ deleg
        if e.deleg_type == OPEN_DELEGATE_READ and \
                not (access & OPEN4_SHARE_ACCESS_WRITE):
            return False
        else:
            return True

    def recall_conflicting_delegations(self, dispatcher, client, access, deny):
        # NOTE OK to have extra access/deny flags
        if not self.conflicts(client, access, deny):
            return
        # Recall everything
        for e in self._tree.itervalues():
            if e.status == NORMAL:
                e.status = CB_INIT
                t = threading.Thread(target=e.initiate_recall,
                                     args=(dispatcher,))
                t.setDaemon(True)
                t.start()
        # We need to release the lock so that delegations can be recalled,
        # which can involve operations like WRITE, LOCK, OPEN, etc,
        # that would otherwise block.  The easiest way to do this is to
        # initiate shut down of this thread.
        raise NFS4Error(NFS4ERR_DELAY)

    def grant_delegation(self, open_state, access):
        # FIXME
#        if self.waiting > 0 or self.outstanding > 0:
#            # Don't grant delegations while anyone is waiting for a recall
#            return None
        if access & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK == \
           OPEN4_SHARE_ACCESS_WANT_NO_DELEG:
            return None
        # Need to query file (or fs?).  For example, ConfigFS should
        # never grant delegation.
        possible = self.file.delegation_options()
        if not (possible & OPEN_DELEGATE_READ):
            return None
        # STUB - just grant read delegation if don't have it already
        # FIXME - previously, if already had a delegation, returned None,
        # now we return it again - will this cause problems?
        entry = self.grab_entry(open_state.key[:1], DelegEntry)
        entry.open_state = open_state
        log.debug("GRANTING delegation: %s" % open_delegation_type4[entry.deleg_type])
        return entry

class AnonState(FileStateTyped):
    type = ANON
    def __init__(self, *args, **kwargs):
        kwargs["depth"] = 1 # key = (int,)
        FileStateTyped.__init__(self, *args, **kwargs)
        self._tree[(0 ,)] = AnonEntry("\x00" * 12, self, (0,))
        self._tree[(1 ,)] = AnonEntry("\xff" * 12, self, (1,))
        self._tree[(DS_MAGIC, )] = DSEntry(DS_MAGIC * 12, self, (DS_MAGIC, ))

class ShareState(FileStateTyped):
    """Holds share state for a single file"""
    type = SHARE

    def __init__(self, *args, **kwargs):
        kwargs["depth"] = 2 # key = (client, open_owner)
        FileStateTyped.__init__(self, *args, **kwargs)
        self.cache_valid = True # Are the cached values valid?
        self.cached_access = self.cached_deny = 0 # When valid, union of all values

    def close(self, key):
        del self._tree[key]

    def add_share(self, client, owner, access, deny):
        """An open wants to add its share state to the file."""
        # Is this test_share necessary?  It's duplicated in the caller of add_share
        self.file.state.test_share(access, deny)
        entry = self.grab_entry((client, owner), ShareEntry)
        entry.add_share(access, deny)
        self.cache_valid = False
        return entry

    def _test_share(self, access, deny, error, anon):
        """Check (access, deny) against all current shares.

        Raises error if there is a conflict.
        """
        # OK to use full access/deny
        if self.cache_valid:
            current_access, current_deny = self.cached_access, self.cached_deny
        else:
            # See draft22 9.7
            current_access = current_deny = 0
            for entry in self.itervalues():
                current_access |= entry.share_access
                current_deny |= entry.share_deny
            self.cached_access, self.cached_deny = current_access, current_deny
            self.cache_valid = True
        current_access |= anon
        if access & current_deny or deny & current_access:
            raise NFS4Error(error)

class ByteState(FileStateTyped):
    """Holds byte range lock state for a single file"""
    type = BYTE

    def __init__(self, *args, **kwargs):
        kwargs["depth"] = 3 # key = (client, open_owner, lock_owner)
        FileStateTyped.__init__(self, *args, **kwargs)
        # self.state =  {} # {client: {open_owner: {lock_owner:entry}}}

#     def add_lock(self, client, open_owner, lock_owner, type, start, end):
#         self.test_lock(xxx)
#         self.grab_entry((client, open_owner, lock_owner), ByteEntry)
#         entry.add_lock(type, start, end)

    def has_locks(self, client, open_owner=None, lock_owner=None):
        return self._tree.hasbranch((client, open_owner, lock_owner))

#     def remove_locks(self, client, open_owner=None, lock_owner=None):
#         # del self.state[(client, open_owner, lock_owner)]
#         key = (client, open_owner, lock_owner)
#         self.remove(key)
    def find_conflicts(self, key_template, range):
        """See if range conflicts with any lock not matching template

        Raises error containing info on a conlicting lock if any found.
        """
        def match(template, key):
            for i,j in zip(template, key):
                if i==j or i is None:
                    return True
            return False
        for e in self._tree.itervalues():
            if match(key_template, e.key):
                # Ignore locks in subtree indicated by key
                continue
            for lock in e.locks:
                if range.conflicts(lock):
                    if lock.expired:
                        # STUB - expired always returns False
                        pass
                    # Set up the exception
                    if lock.end == 0xffffffffffffffff:
                        dlength = 0xffffffffffffffff
                    else:
                        dlength = lock.end + 1 - lock.start
                    owner = lock_owner4(e.key[0].clientid, e.key[-1])
                    lock_denied = LOCK4denied(lock.start, dlength,
                                              lock.type, owner)
                    raise NFS4Error(NFS4ERR_DENIED, lock_denied=lock_denied)

    def _create_lockowner(self, key):
        """Create a new ByteEntry associated with lockowner.

        What if it already exists???
        """
        return self.grab_entry(key, ByteEntry)

class LayoutState(FileStateTyped):
    type = LAYOUT

    def __init__(self, *args, **kwargs):
        kwargs["depth"] = 1 # key = (client,)
        FileStateTyped.__init__(self, *args, **kwargs)

    def grant_layout(self, state, layoutargs):
        # FIXME
        #if self.waiting > 0 or self.outstanding > 0:
        ## Don't grant layouts while anyone is waiting for a recall
        #   return None
        if self.file.layout_options() == layoutargs.loga_layout_type:
            entry = self.grab_entry(state.key[:1], LayoutEntry)
            layout = self.file.get_layout(layoutargs)
            entry.populate(layout)
            log.debug("GRANTING layout: %s" % layout)
            return layout, entry
        raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)

class FileState(object):
    """Holds all state for a file."""
    def __init__(self, file):
        self.lock = lock = Lock("StateLock_%i" % file.id)
        self.file = file
        self.types = (ShareState(file, lock), ByteState(file, lock),
                      DelegState(file, lock), LayoutState(file, lock),
                      AnonState(file, lock))
        # Pass through the following attributes
        self.anon0 = self.types[ANON][(0,)]
        self.anon1 = self.types[ANON][(1,)]
        self.add_share = self.types[SHARE].add_share
        self.recall_conflicting_delegations = \
            self.types[DELEG].recall_conflicting_delegations
        self.grant_delegation = self.types[DELEG].grant_delegation
        self._create_lockowner = self.types[BYTE]._create_lockowner
        #self.delegreturn = self.types[DELEG].delegreturn
        self.grant_layout = self.types[LAYOUT].grant_layout

    def __enter__(self):
        self.lock.acquire()

    def __exit__(self, t, v, tb):
        self.lock.release()

    def test_share(self, access, deny=OPEN4_SHARE_DENY_NONE,
                   error=NFS4ERR_SHARE_DENIED, client=None):
        """Check (access, deny) against all current shares.

        Raises error if there is a conflict.
        """
        if access & 3 == 0:
            raise NFS4Error(NFS4ERR_INVAL)
        anon = 0
        if self.anon0.read_count:
            anon |= OPEN4_SHARE_ACCESS_READ
        if self.anon0.write_count:
            anon |= OPEN4_SHARE_ACCESS_WRITE
        self.types[SHARE]._test_share(access, deny, error, anon)

    def close(self, key): # key = (client, open_owner)
        # client.config.allow_close_with_locks
        if self.types[BYTE].has_locks(key):
            if not client.config.allow_close_with_locks:
                raise NFS4Error(NFS4ERR_LOCKS_HELD)
            self.types[BYTE].remove_locks(key)
        self.types[SHARE].close(key)
        if self.has_no_state():
            # BUG - ignores file locking
            if self.file.fattr4_numlinks == 0:
                self.file.destroy()

    def has_no_state(self):
        # STUB - used by close
        return False

    def test_lock(self, client, lock_owner, type, start, end):
        new_lock = ByteLock(type, start, end)
        self.types[BYTE].find_conflicts((client, None, lock_owner), new_lock)

class StateTableEntry(object):
    """This is the object that is referenced by a stateid.

    It is basically a leaf of the FileState tree, describing a single lock.

    NOTE is is assumed that the lock is held pretty much the entire time
    the structure is in use.
    """
    def __init__(self, other, state, key):
        self.other = other # 'other' field of stateid4
        self.lock = state.lock # lock shared with FileState()
        self.file = state.file
        self._state = state # FileStateTyped in which Entry is embedded
        self.key = key   # key used to store in Tree
        self.seqid = 0   # last seqid sent out as part of stateid4. See 8.1.3.1
        self._private_lock = threading.Condition() # Non-shared lock
        self.invalid = False # Set True when no longer embedded in tree
        self.read_count = 0
        self.write_count = 0
#         if type == BYTE:
#             self.locklist = []

    def has_permission(self, access):
        raise NotImplementedError

    def mark_reading(self):
        with self._private_lock:
            self.read_count += 1

    def mark_done_reading(self):
        with self._private_lock:
            self.read_count -= 1
            if self.read_count + self.write_count == 0:
                self._private_lock.notifyAll()

    def mark_writing(self):
        with self._private_lock:
            self.write_count += 1

    def mark_done_writing(self):
        with self._private_lock:
            self.write_count -= 1
            if self.write_count + self.write_count == 0:
                self._private_lock.notifyAll()

    def wait_until_unused(self):
        # Only call this if holding self.lock
        with self._private_lock:
            if self.read_count + self.write_count!= 0:
                self._private_lock.wait()

    def get_id(self, cb=False):
        """Return stateid4 associated with this state.

        NOTE assumes lock is held.
        """
        if cb:
            # seqid zeroed for callbacks per draft22 8.2.2
            return stateid4(0, self.other)
        else:
            # BUG - only increment if has changed
            # NOTE - careful about only inc if change, see draft22 9.9
            self.seqid = nfs4lib.inc_u32(self.seqid)
            return stateid4(self.seqid, self.other)

    def delete(self):
        """Remove this entry from self.file.state table"""
        self.invalid = True
        del self._state._tree[self.key]
        del self.key[0].state[self.other]

class DSEntry(StateTableEntry):
    """Hack to ignore data server state"""
    type = ANON
    def has_permission(self, access):
        pass

    def close(self):
        pass

    def populate(self, layout):
        pass

class AnonEntry(StateTableEntry):
    """Handle special anonymous stateids

    Note that there are only two instances of this class per file, for key 0
    and 1.  The all zero special stateid always maps to the key==0 object.
    However, the all ones special stateid may map to either, depending on how
    it is used.
    """
    # STUB - I suspect this should look more like ShareEntry
    type = ANON
    def __init__(self, other, state, key):
        super(AnonEntry, self).__init__(other, state, key)

    def has_permission(self, access):
        # Note for an anon entry, we are not checking if the state grants
        # permission, but that it does not conflict with anybody else

        # Error due to draft23 9.1.2: "when the OPEN denies READ or WRITE
        # operations, that denial results in such operations being rejected
        # with error NFS4ERR_LOCKED"
        if self.key != (1, ):
            self.file.state.test_share(access, error=NFS4ERR_LOCKED)

class ShareEntry(StateTableEntry):
    type = SHARE

    def __init__(self, other, state, key):
        super(ShareEntry, self).__init__(other, state, key)
        # 2 bit value normally used
        self.share_access = self.share_deny = 0
        # 3 bit value used to record history of unions, just so we
        # can implement (from 18.18.3 of draft 22):
        # The bits ... SHOULD equal the union of the ... bits specified
        # for some subset of the OPENs in effect for the current open-owner
        # on the current file.
        self.access_hist = self.deny_hist = 0

    def has_permission(self, access):
        """Verify access against current share"""
        if (not self.share_access) or \
                (access == OPEN4_SHARE_ACCESS_WRITE and
                 not (self.share_access & OPEN4_SHARE_ACCESS_WRITE)):
            raise NFS4Error(NFS4ERR_OPENMODE)

    def add_share(self, access, deny):
        self.share_access |= (access & 3)
        self.share_deny |= (deny & 3)
        self.access_hist |= self.__2to3(access)
        self.deny_hist |= self.__2to3(deny)

    def __2to3(self, value):
        """OPEN_DOWNGRADE requires us to store a 'history' of values.

        This basically amounts to being able to distinguish 11 from
        01 | 10.  So we transform 11 to 100 and use that.
        """
        value &= 0x07
        if value == 0x03:
            return 0x04
        else:
            return value

#     # Is this used anywhere???
#     def __3to2(self, value):
#         """Undo __2to3 transfrom"""
#         if value == 0x04:
#             return 0x03
#         else:
#             return value

#     def remove_share(self, access, deny):
#         """Downgrade shares.  access == deny == 0 removes shares completely"""
#         new_access = self.__2to3(access)
#         new_deny = self.__2to3(deny)
#         if new_access & ~self.access_hist or new_deny & ~self.deny_hist:
#             # This test is the whole reason for the silly 3-bit
#             # representation.  It basically prevents the seqence
#             # OPEN(share=BOTH), OPENDOWNGRADE(share=SINGLE).
#             raise NFS4Error(NFS4ERR_INVAL, tag="Failed history test")
#         if access == 0 and deny != 0:
#             raise NFS4Error(NFS4ERR_INVAL, tag="access==0")
#         self.access_hist, self.deny_hist = new_access, new_deny
#         self.share_access, self.share_deny = access, deny

    def close(self):
        """Close the file, removing all share data.

        Note this is a bit tricky, since must interact with other state types.
        """
        self.file.state.close(self.key)

    def create_lockowner(self, lockowner):
        """Create a lockowner dependent on this openowner."""
        newkey = list(self.key)
        newkey.append(lockowner)
        entry = self.file.state._create_lockowner(newkey)
        entry.open_state = self
        return entry

class DelegEntry(StateTableEntry):
    type = DELEG

    def __init__(self, other, state, key):
        super(DelegEntry, self).__init__(other, state, key)
        self.deleg_type = OPEN_DELEGATE_READ
        self.status = NORMAL

    def delegreturn(self):
        self.status = INVALID
        self.delete()

    def has_permission(self, access):
        # From draft23 9.1.2:
        # "For delegation stateids the access mode is based on the type of
        #  delegation"
        if access == OPEN4_SHARE_ACCESS_WRITE and \
                self.deleg_type == OPEN_DELEGATE_READ:
            raise NFS4Error(NFS4ERR_OPENMODE) # Is this the correct error???

    def initiate_recall(self, dispatcher):
        """Handle CB_RECALL for this delegation.

        It is called in its own thread.
        """
        # STUB
        # find active callback channel
        # send CB_RECALL
        # listen for reply
        # monitor progress?
        # DELEGRETURN or lease expiry should del self.state[client]
        #   if that was last, should notify waiting threads that all
        #   delegs have been returned
        log.debug("Recalling delegation %r" % self.other)
        client = self.key[0]
        session = client.find_active_cb_session()
        if session is None:
            # BUG deal with this
            raise RuntimeError
        # NOTE that we come in w/o state lock...when should we grab it?
        # ANSWER - we care about self.status, which can be set to
        # INVALID anytime by deleg_return
        slot = session.channel_back.choose_slot()
        seq_op = op4.cb_sequence(session.sessionid, slot.get_seqid(),
                                slot.id, slot.id, True, []) # STUB
        recall_op = op4.cb_recall(self.get_id(cb=True), False, self.file.fh)
        if self.invalid:
            # Race here doesn't matter, but would like to avoid the
            # RPC if possible.
            self.status = INVALID
            return
        # All sorts of STUBBINESS here
        pipe = session.channel_back.connections[0]
        xid = dispatcher.cb_compound_async([seq_op, recall_op],
                                           session.cb_prog, pipe=pipe)
        # Note it is possible that self.invalid is True, but don't
        # want to take the lock
        self.status = CB_SENT
        res = dispatcher.cb_listen(xid, pipe)
        session.channel_back.free_slot(slot.id)
        with self.lock:
            if res.status != NFS4_OK:
                # NOTE - this could 'legit' occur if client sends DELEG_RETURN
                # and get OK before responding to CB_RECALL, could happen
                # if client spontaneously sends DELEG_RETURN about the same
                # time server sends CB_RECALL
                # STUB - now what???
                raise RuntimeError
            self.status = (CB_RECEIVED if not self.invalid else INVALID)

class ByteEntry(StateTableEntry):
    type = BYTE

    # From draft23 9.1.2: "the appropriate mode is the access mode for the
    # open stateid associated with the lock"
    has_permission = property(lambda s: s.open_state.has_permission)

    def __init__(self, other, state, key):
        super(ByteEntry, self).__init__(other, state, key)
        self.locks = [] # The list of ByteLocks associated with key

    def add_lock(self, type, start, end):
        """Try to add a lock for the lockowner implicit in self.key."""
        new_lock = ByteLock(type, start, end)
        self._state.find_conflicts(self.key, new_lock)
        # BUG this code does not fully comply with draft22 9.5
        if POSIXLOCK:
            self.add_posix_lock(new_lock)
        else:
            for lock in self.locks:
                if lock.overlaps(start, end, exact=True):
                    # Up/downgrade existing lock
                    lock.type = type
                    return
            self.locks.append(new_lock)

    def remove_lock(self, type, start, end):
        """Try to remove a lock for the lockowner implicit in self.key."""
        old_lock = ByteLock(type, start, end)
        # Note type is ignored per draft22 18.12.3:
        # "Any legal value for locktype has no effect on the success or
        # failure of the LOCKU operation."
        if POSIXLOCK:
            self.remove_posix_lock(old_lock)
        else:
            try:
                self.locks.remove(old_lock)
            except ValueError:
                raise NFS4Error(NFS4ERR_LOCK_RANGE)

#     def add_posix_lock(self, type, start, end):
#         """Adds lock to list, splitting/merging existing locks as necessary"""
#         self.remove_posix_lock(start, end)
#         list = self.locklist
#         if not list:
#             list.append(ByteLock(type, start, end))
#             return
#         i = 0
#         while (list and list[i].end < start):
#             i += 1
#         list.insert(i, ByteLock(type, start, end))
#         # Merge adjacent locks
#         # Really want range(i+1, i-1, -1), but need to account for list edges
#         for i in range(min(i+1, len(list)-1), max(1,i)-1, -1):
#             if i > 0 and list[i].start == list[i-1].end + 1 and \
#                list[i].type == list[i-1].type:
#                 list[i-1].end == list[i].end
#                 del list[i]

#     def remove_posix_lock(self, start, end):
#         """Removes locks in given range, shrinking locks that half-overlap"""
#         new = []
#         for lock in self.locklist:
#             if start <= lock.start and lock.end <= end:
#                 # Lock is contained in range, and should be removed
#                 continue
#             new.append(lock)
#             # Look for lock overhanging range, it must be shrunk or split
#             if lock.start < start <= lock.end:
#                 if end < lock.end:
#                     new.append(ByteLock(lock.type, end + 1, lock.end))
#                 lock.end = start - 1
#             elif lock.start <= end < lock.end:
#                 lock.start = end + 1
#             elif end < lock.start:
#                 break
#         self.locklist = new

class LayoutEntry(StateTableEntry):
    type = LAYOUT

    def __init__(self, other, state, key):
        super(LayoutEntry, self).__init__(other, state, key)

    def populate(self, layout):
        # Need to record here what we have handed out so far
        pass
