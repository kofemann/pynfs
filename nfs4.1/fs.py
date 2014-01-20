from nfs4state import FileState
from nfs4_const import *
from nfs4_type import fsid4, layout4, layout_content4, nfsv4_1_file_layout4
import nfs4lib
from nfs4lib import NFS4Error
import struct
import logging
from locking import Lock, RWLock
from cStringIO import StringIO
import time
from nfs4_pack import NFS4Packer

log_o = logging.getLogger("fs.obj")
log_fs = logging.getLogger("fs")
logging.addLevelName(5, "FUNCT")
log_fs.setLevel(20)

class MetaData(object):
    """Contains everything that needs to be stored

    to preserve all of the object's metadata.
    """
    def __init__(self):
        self.change = 0
        self.type = 0
        self.refcnt = 0
        self.createverf = ""
        self.owner = ""
        self.mode = 0777
        self.time_access = self.time_modify = self.time_create = nfs4lib.get_nfstime()
        if 1:
            self.parent = 0
        if 1:
            self.linkdata = None
            self.devdata = None

class FSObject(object):
    """This is the in-memory depiction of an (nfs4) file-system object.

    Currently, it is kept in sync with the disk via a lock within self.state.
    This will keep read/writes current, but will not work with
    attrs and non NF4REG files.
    """

    # NOTE that any change to these attrs needs to be eventually
    #      written to disk
    def _getfh(self):
        # STUB - this will probably need to be revised
        # We encode fsid as 16 bytes, then a byte of flags, then append id
        # id should be an opaque<100>
        # NOTE - use of id for fattr4_fileid limits size to 8 bytes
        major, minor = self.fs.fsid
        return struct.pack("!QQbQ", major, minor, 0, self.id)

    def _getsize(self):
        with self.seek_lock:
            return self._getsize_locked()

    def _getsize_locked(self):
        # STUB
        if self.fattr4_type == NF4REG:
            if hasattr(self.file, "__len__"):
                return len(self.file)
            else:
                orig = self.file.tell()
                self.file.seek(0, 2)
                eof = self.file.tell()
                self.file.seek(orig)
                return eof
        elif self.fattr4_type == NF4DIR:
            return len(self.entries)
        else:
            return 0

    def _setsize(self, value):
        with self.seek_lock:
            return self._setsize_locked(value)

    def _setsize_locked(self, value):
        # STUB - How should this behave on non REG files? especially a DIR?
        size = self._getsize_locked()
        if self.fattr4_type == NF4REG:
            if value == size:
                return
            elif value < size:
                self.file.truncate(value)
            else:
                # Pad with zeroes
                self.file.seek(0, 2)
                self.file.write(chr(0) * (value - size))
            self.change_data()
        else:
            raise NFS4Error(NFS4ERR_INVAL)

    def _setmode(self, value):
        self.meta.mode = value

    def _set_time_access(self, value):
        if value.set_it == SET_TO_CLIENT_TIME4:
            self.meta.time_access = value.time
        else:
            self.meta.time_access = nfs4lib.get_nfstime()

    def _set_time_modify(self, value):
        if value.set_it == SET_TO_CLIENT_TIME4:
            self.meta.time_modify = value.time
        else:
            self.meta.time_modify = nfs4lib.get_nfstime()

    def _get_mounted_on_fileid(self):
        if self == self.fs.root:
            obj = (self.fs.mounted_on if self.fs.mounted_on else self)
        else:
            obj = self
        return obj.fattr4_fileid

    def _set_owner(self, value):
        # STUB - do some utf8 checking here
        self.owner = value

    fh = property(_getfh)
    fattr4_filehandle = fh
    fattr4_size = property(_getsize, _setsize)
    fattr4_change = property(lambda s: s.change)
    fattr4_type = property(lambda s: s.type)
    fattr4_fsid = property(lambda s: fsid4(*(s.fs.fsid)))
    fattr4_fileid = property(lambda s: s.id)
    fattr4_owner = property(lambda s: s.owner, _set_owner)
    fattr4_mounted_on_fileid = property(_get_mounted_on_fileid)
    fattr4_numlinks = property(lambda s: s.refcnt)
    fattr4_time_access_set = property(lambda s: s.time_access, _set_time_access)
    fattr4_time_modify_set = property(lambda s: s.time_modify, _set_time_modify)
    fattr4_time_access = property(lambda s: s.time_access)
    fattr4_time_modify = property(lambda s: s.time_modify)
    fattr4_mode = property(lambda s: s.mode, _setmode)
    isdir = property(lambda s: s.type == NF4DIR)
    isfile = property(lambda s: s.type == NF4REG)
    isempty = property(lambda s: s.entries == {})

    def __init__(self, fs, id, kind=NF4DIR, parent=None):
        log_o.log(5, "FSObject.__init__(id=%r)" % id)
        self.meta = None # HACK - meta must be set immediately for
        #                 __setattr__ and __getattr__ to work properly
        self.fs = fs
        self.id = id
        if isinstance(kind, MetaData):
            # Object is being regenerated from disk
            self.meta = kind
            self._last_sync = self.meta.change
        else:
            # Object is being created for first time
            self.meta = MetaData()
            if type(kind) is int:
                self.type = kind
            else:
                self.type = kind.type
                if self.type == NF4LNK:
                    self.linkdata = kind.linkdata
                elif self.type in (NF4BLK, NF4CHR):
                    self.devdata = kind.devdata
            self.change = 0 # XXX Not really needed
            self.createverf = "" # XXX Not really needed
            self._last_sync = -1
            if 1: # NF4REG
                self.file = self.init_file()
            if 1: # NF4DIR
                # Can't store FSObj, since needs to be pickled
                self.parent = getattr(parent, "id", None)
                self.entries = {} # {name:id}
        if 1: # NF4DIR
            self.dircache = {}
        self.state = FileState(self)
        self._set_fattrs()
        self.lock = RWLock(name=str(id))
        self.seek_lock = Lock("SeekLock")
        self.current_layout = None
        self.covered_by = None # If this is a mountpoint for fs, equals fs.root 
        # XXX Need to write to disk here?
        self._init_hook()

    def init_file(self):
        """Hook for subclasses that want to use their own file class"""
        return StringIO()

    def _init_hook(self):
        pass

    def __setattr__(self, name, value):
        if name != "meta" and hasattr(self.meta, name):
            setattr(self.meta, name, value)
        else:
            object.__setattr__(self, name, value)

    def __getattr__(self, name):
        # Note only get here if self.name does not exist
        return getattr(self.meta, name)

    def _set_fattrs(self):
        self.fattr4_rdattr_error = NFS4_OK # NOTE does this need sent to disk?
        self.fattr4_named_attr = False # STUB - not supported, so not in meta

    def check_dir(self):
        if self.type not in (NF4DIR, NF4ATTRDIR):
            if self.type == NF4LNK:
                raise NFS4Error(NFS4ERR_SYMLINK)
            else:
                raise NFS4Error(NFS4ERR_NOTDIR)

    def verify_file(self, notelink=False):
        if self.type != NF4REG:
            if notelink:
                d = {NF4DIR: NFS4ERR_ISDIR, NF4LNK: NFS4ERR_SYMLINK}
            else:
                d = {NF4DIR: NFS4ERR_ISDIR}
            raise NFS4Error(d.get(self.type, NFS4ERR_INVAL))

    def change_data(self):
        self.change += 1
        # STUB reset time_* attrs

    def change_meta(self):
        self.change += 1
        # STUB reset time_* attrs

    def change_access(self):
        self.change += 1
        # STUB reset time_* attrs

    def delegation_options(self):
        if self.type != NF4REG:
            return 0
        else:
            return self.fs.delegation_options()

    def layout_options(self):
        if self.type != NF4REG:
            return 0
        else:
            return self.fs.layout_options()

    def close(self):
        self.sync(FILE_SYNC4)

    def sync(self, how=FILE_SYNC4):
        """Write to disk, according to how"""
        log_o.log(5, "FSObject(id=%i).sync()" % self.id)
        if self._last_sync == self.change:
            log_o.log(5, "sync skipped")
            return FILE_SYNC4
        if how == UNSTABLE4: # XXX This could be incorporated into fs.sync()
            return UNSTABLE4
        rv = self.fs.sync(self, how)
        if rv == FILE_SYNC4:
            self._last_sync = self.change
        return rv

    def write(self, data, offset, principal): # NF4REG only
        """Return count of bytes written"""
        if not self.access4_modify(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        if len(data) == 0:
            return 0
        with self.seek_lock:
            self.file.seek(offset)
            try:
                self.file.write(data)
            finally:
                self.change_data()
        return len(data)

    def read(self, offset, count, principal): # NF4REG only
        if not self.access4_read(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        with self.seek_lock:
            self.file.seek(offset)
            data = self.file.read(count)
        self.change_access()
        return data

    def destroy(self):
        """Remove from disk"""
        log_o.info("***DESTROY*** id=%i" % self.id)
        # STUB
        pass

##     def set_fattr4_size(self, newsize):
##         # FRED - How should this behave on non REG files? especially a DIR?
##         if self.fattr4_type == NF4REG and newsize != self.fattr4_size:
##             if newsize < self.fattr4_size:
##                 self.file.truncate(newsize)
##             else:
##                 # Pad with zeroes
##                 self.file.seek(0, 2)
##                 self.file.write(chr(0) * (newsize-self.fattr4_size))
##             self.fattr4_size = newsize
##             self.fattr4_time_modify = converttime()
##         else:
##             raise NFS4Error(NFS4ERR_INVAL)

    def set_attrs(self, attrs, principal=None):
        """Set attributes and return bitmask of those set

        attrs is of form {bitnum:value}
        For each bitnum, it will try to call self.set_fattr4_<name> if it
        exists, otherwise it will just set the variable self.fattr4_<name>.
        """
        # STUB - need to check principal, and set owner/group if needed
        log_o.log(5, "FSObject.set_attrs(%r)" % attrs)
        info = nfs4lib.attr_info
        bitmap = 0L
        try:
            for attr in attrs:
                if self.fs.fattr4_supported_attrs & attr == 0:
                    raise NFS4Error(NFS4ERR_ATTRNOTSUPP, attrs=bitmap,
                                    tag = "unsupported attribute %i" % attr)
                if not info[attr].writable:
                    raise NFS4Error(NFS4ERR_INVAL, attrs=bitmap,
                                    tag = "attr %i not writable" % attr)
                name = "fattr4_%s" % nfs4lib.attr_name(attr)
                # Note all writable attrs are object attrs
                if hasattr(self, name):
                    base = self
                else:
                    base = self.meta
                try:
                    setattr(base, name, attrs[attr])
                except NFS4Error, e:
                    # Note attributes set so far in any error that occurred
                    e.attrs = bitmap
                    raise
                bitmap |= (1 << attr)
        finally:
            if bitmap:
                self.change_meta()
        return bitmap

    def layout_open_hook(self):
        """Called when a file is about to be opened"""
        # STUB - this is used currently for filelayout, but input/output
        # need to be better thought through
        return

    def layout_close_hook(self):
        """Called when a file is about to be opened"""
        # STUB - this is used currently for filelayout, but input/output
        # need to be better thought through
        return

    def get_layout(self, arg):
        """Takes as input LAYOUTGET4args, returns layout4,

        or raises the appropriate error.
        NOTE permissions checking on the range has already been done
        """
        fs = self.fs
        if not fs.fattr4_supported_attrs & (1 << FATTR4_FS_LAYOUT_TYPES):
            raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)
        try:
            types = fs.fattr4_fs_layout_type
        except:
            raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)
        if arg.loga_layout_type not in types:
            raise NFS4Error(NFS4ERR_UNKNOWN_LAYOUTTYPE)
        if self.current_layout:
            # STUB - should be able to expand layout
            if 0:
                # This isn't working, because don't have commit done
                raise NFS4Error(NFS4ERR_LAYOUTTRYLATER)
        return self._get_layout(arg)

    def _get_layout(self, arg):
        raise NotImplementedError

    def commit_layout(self, arg):
        fs = self.fs
        if arg.loca_reclaim:
            # STUB - this is just not supported
            raise NFS4Error(NFS4ERR_NO_GRACE)
        if not fs.fattr4_supported_attrs & (1 << FATTR4_FS_LAYOUT_TYPES):
            raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)
        if not self.current_layout:
            raise NFS4Error(NFS4ERR_BADLAYOUT, tag="File has no layout")
        if self.current_layout[3] != LAYOUTIOMODE4_RW:
            raise NFS4Error(NFS4ERR_BADLAYOUT, tag="Committing to a ro layout")
        return self._commit_layout(arg)

    def _commit_layout(self, arg):
        raise NotImplementedError

    def access4_read(self, principal):
        """Returns True if principal can read object."""
        # STUB
        return True

    def access4_lookup(self, principal):
        """Returns True if principal can look up name in directory."""
        # STUB
        return self.type == NF4DIR

    def access4_modify(self, principal):
        """Returns True if principal can change existing object data."""
        # STUB
        return (not self.fs.read_only) or (principal.skip_checks)

    # STUB - don't differentiate between extend and modify
    access4_extend = access4_modify

    def access4_delete(self, principal):
        """Returns True if principal can delete a directory entry."""
        # STUB
        return self.type == NF4DIR

    # Per draft-29, sect 18.1.13, this really should be undefined.
    # However, the linux client needs it to execute a file from
    # the NFS directory.
    #
    # "If the server does not support execute permission bits or some
    # other method for denoting executability, it MUST NOT set
    # ACCESS4_EXECUTE in the reply's supported and access fields"
    def access4_execute(self, principal):
        return True

    #######################
    # These all assume is a directory
    #######################
    def exists(self, name):
        """Returns True if name is in the dir"""
        log_o.log(5, "FSObject.exists(%r)" % name)
        if self.type != NF4DIR: # XXX STUB, also need to handle attrdir
            raise RuntimeError("Bad type %i" % self.type)
        id = self.entries.get(name, None)
        return id is not None

    def lookup(self, name, client, principal, follow_mount=True):
        """Returns object associated with name in the dir, following mounts."""
        log_o.log(5, "FSObject.lookup(%r, %r)" % (name, principal))
        # We don't do utf8 checks here, since are fs variations
        if self.type != NF4DIR: # XXX STUB, also need to handle attrdir
            raise RuntimeError("Bad type %i" % self.type)
        if not self.access4_lookup(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        id = self.entries.get(name)
        if id is None:
            return None
        obj = self.fs.find(id)
        if follow_mount:
            while obj.covered_by is not None:
                # Directory is hidden by a mount
                obj = obj.covered_by
        return obj

    def lookup_parent(self, client, principal):
        """Returns object which is parent of current dir."""
        log_o.log(5, "FSObject.lookup_parent(%r)" % (principal))
        # We don't do utf8 checks here, since are fs variations
        if self.type not in [NF4DIR, NF4ATTRDIR]:
            raise NFS4Error(NFS4ERR_NOTDIR) # Per draft23 18.14.3, line 23599
        dir = self
        while dir.parent is None:
            # At fs.root, so find parent of dir hidden by mount
            dir = dir.fs.mounted_on
            if dir is None:
                # We are at the server root
                raise NFS4Error(NFS4ERR_NOENT) # Per draft23 18.14.3
        id = dir.parent
        return dir.fs.find(id)

    def link(self, name, obj, principal):
        """Adds obj to the dir as name"""
        log_o.log(5, "FSObject.link(%r), fsid=%r" % (name, self.fs.fsid))
        if name in self.entries:
            raise RuntimeError
        if not self.access4_extend(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        self.entries[name] = obj.id
        self.change_data()
        if obj.isdir:
            obj.parent = self.id
        # BUG - does obj.lock need to be held?
        obj.refcnt += 1

    def unlink(self, name, principal): # NF4DIR only
        """Removes name from directory"""
        # STUB - do some principal checking
        log_o.log(5, "FSObject(id=%i).unlink(%r)" % (self.id, name))
        obj = self.lookup(name, None, principal)
        if not self.access4_delete(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        obj.lock.acquire_write()
        try:
            if obj.isdir and not obj.isempty:
                raise NFS4Error(NFS4ERR_NOTEMPTY)
            obj.refcnt -= 1
            obj.sync()
        finally:
            obj.lock.release()
        del self.entries[name]

    def readdir(self, verifier, client, principal):
        """Returns list of (name, obj) pairs"""
        # STUB - this API will certainly change
        # need to think how to deal with cookies
        log_o.log(5, "FSObject.readdir()")
        if not self.access4_read(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        t = struct.unpack(">d", verifier)[0]
        if t != 0.0:
            try:
                return self.dircache[t], verifier
            except KeyError:
                raise NFS4Error(NFS4ERR_NOT_SAME)
        res = [(name, self.fs.find(id)) for name, id in self.entries.items()]
        while len(self.dircache) >= 4:
            # Clean out old cache entries
            # NOTE this system is problematic if multiple clients accessing
            del self.dircache[min(self.dircache.keys())]
        t = time.time()
        self.dircache[t] = res
        return res, struct.pack(">d", t)

    def create(self, name, principal, kind, attrs):
        """Create and link a new object into the dir

        kind can be either an int (from enum nfs_ftype4) or a createtype4
        attrs is a dictionary of {bitnum: attr_value}
        """
        log_o.log(5, "FSObject.create(%r, %r)" % (name, principal))
        if not self.access4_extend(principal):
            raise NFS4Error(NFS4ERR_ACCESS)
        obj = self.fs.create(kind, force=principal.skip_checks)
        if FATTR4_OWNER not in attrs:
            # STUB - should also limit ability to arbitrarily set owner
            attrs[FATTR4_OWNER] = principal.name
        bitmask = obj.set_attrs(attrs)
        self.link(name, obj, principal)
        return obj, bitmask

class FileSystem(object):
    def __init__(self, fsid=0, objclass=FSObject):
        log_fs.log(5, "FileSystem.__init__(fsid=%i)" % fsid)
        self.fsid = (1, fsid) # Return a unique 2-tuple of uint64
        self.objclass = objclass
        self._disk_lock = Lock("FSLock")
        self.read_only = False
        # This is list of currently active objects.
        self._ids = {} # {obj.id: obj}
        self._set_fattrs()
        self.mounted_on = None # obj on which fs is mounted
        # Do this last
        self.root = self.create(NF4DIR)       # Points to FSObject
        self.root.refcnt = 1

    def _set_fattrs(self):
        # STUB Mandatory attribute mask = 0x80fff
        # maxname needed
        # fileid and mounted_on_fileid needed for mount traversal
        mandatory = 0x80fff
        need_for_linux = [FATTR4_FILEID, FATTR4_MAXNAME, FATTR4_MOUNTED_ON_FILEID]
        need_for_cthon = [FATTR4_MODE, FATTR4_NUMLINKS]
        # self.fattr4_supported_attrs = 0x80000020180fff
        self.fattr4_supported_attrs = nfs4lib.list2bitmap(need_for_linux + need_for_cthon) | mandatory

        self.fattr4_fh_expire_type = FH4_PERSISTENT
        self.fattr4_link_support = False
        self.fattr4_symlink_support = False
        self.fattr4_unique_handles = False
        ########
        self.fattr4_maxname = 256

    def mount(self, dir):
        """Mount the fs at the given dir.

        A mount covers a dir, and LOOKUP will return the top fs.root, as
        opposed to the now hidden dir.
        Note that 'covered_by' is an attribute of an obj, while 'mounted_on'
        is an attribute of the fs.
        """
        dir.covered_by = self.root
        self.mounted_on = dir

    def attach_to_server(self, server):
        """Called at mount, gives fs a chance to interact with server.

        For example, have server assign deviceids.
        """
        pass

    def get_devicelist(self, kind, verf):
        """Returns list of deviceid's of type kind, using verf for caching."""
        # Default for non-pnfs systems
        return []

    def delegation_options(self):
        # Possible delegations fs supports on regular files
        return OPEN_DELEGATE_READ

    def layout_options(self):
        return 0

    def find(self, id):
        """ Returns a FSObject with given id

        There should only be one such outstanding.  If it has
        already been passed out, point to same obj.  Otherwise
        read disk info to create a new one.
        Note : cleanup might be helped by sys.getrefcount()
        """
        log_fs.log(5, "FileSystem.find(id=%r)" % id)
        obj = self._ids.get(id, None)
        if obj is not None:
            return obj
        else:
            self._disk_lock.acquire()
            try:
                # It may have been added while we were waiting for the lock
                obj = self._ids.get(id, None)
                if obj is not None:
                    return obj
                # Guess not, create a new in-memory obj using info on disk
                obj = self.find_on_disk(id)
                self._ids[id] = obj
                return obj
            finally:
                self._disk_lock.release()

    def find_on_disk(self, id):
        """Returns a FSObject created from disk info pointed to by id"""
        raise NotImplementedError

    def sync(self, obj, how):
        """Syncs object to disk, returns value from enum stable_how4"""
        raise NotImplementedError

    def create(self, kind, force=False):
        """Allocs disk space and returns a FSObject associated with it.

        Note does not link the FSObject into the FS tree.
        """
        log_fs.log(5, "FileSystem.create(kind=%r)" % kind)
        if self.read_only and not force:
            raise NFS4Error(NFS4ERR_ROFS, tag="fs.create failed")
        # Huge STUB
        id = self.alloc_id()
        try:
            obj = self.objclass(self, id, kind)
            self._ids[id] = obj # XXX Not needed if object creation does it
        except:
            log_fs.exception("fs.create failed")
            # traceback.print_exc()
            self.dealloc_id(id)
        return obj

    def alloc_id(self):
        """Alloc disk space for an FSObject, and return an identifier
        that will allow us to find the disk space later.
        """
        raise NotImplementedError

    def dealloc_id(self, id):
        """Free up disk space associated with id. """
        raise NotImplementedError

class RootFS(FileSystem):
    def __init__(self):
        self._nextid = 0
        FileSystem.__init__(self)
        self.fattr4_maxwrite = 4096
        self.fattr4_maxread = 4096
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXWRITE
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXREAD
        self.fsid = (0,0)
        self.read_only = True

    def alloc_id(self):
        self._nextid += 1
        return self._nextid

    def dealloc_id(self, id):
        pass

    def sync(self, obj, how):
        return FILE_SYNC4

class StubFS_Mem(FileSystem):
    def __init__(self, fsid):
        self._nextid = 0
        FileSystem.__init__(self)
        self.fsid = (2, fsid)

    def alloc_id(self):
        """Alloc disk space for an FSObject, and return an identifier
        that will allow us to find the disk space later.
        """
        self._nextid += 1
        return self._nextid

    def dealloc_id(self, id):
        """Free up disk space associated with id. """
        pass

    def sync(self, obj, how):
        return FILE_SYNC4

from config import ServerPerClientConfig, ConfigAction

class ConfigObj(FSObject):
    def associate(self, configline):
        self.configline = configline
        self._reset()

    def _reset(self):
        self.file = StringIO()
        self.file.write("# %s\n" % self.configline.comment)
        value = self.configline.value
        if type(value) is list:
            self.file.write(" ".join([str(i) for i in value]))
        else:
            self.file.write("%r\n" % value)
        self.change_data()
        self.dirty = False

    def change_data(self):
        FSObject.change_data(self)
        self.dirty = True

    def create(self, *args, **kwargs):
        raise NFS4Error(NFS4ERR_ACCESS)

    def link(self, *args, **kwargs):
        raise NFS4Error(NFS4ERR_ACCESS)

    def close(self):
        """This verifies any written data

        and either applies the changes or reverts them.
        """
        log_o.log(5, "ConfigObj.close()")
        # Only want to execute this if file has been written
        if not self.dirty:
            return
        lines = []
        for line in self.file.getvalue().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        print lines
        if len(lines) != 1:
            self._reset()
            return
        try:
            self.configline.value = lines[0]
        except ConfigAction, e:
            if e.name == "reboot":
                self.fs.server.reboot()
        except:
            log_o.info("close() verify failed", exc_info=True)
        self._reset()

    def exists(self, name):
        """Returns True if name is in the dir"""
        log_o.log(5, "FSObject.exists(%r)" % name)
        # HACK - build a fake client 
        class Fake(object):
            def __init__(self):
                self.clientid = 0
                self.config = ServerPerClientConfig()
        entries = self._build_entries(Fake())
        return entries.get(name, None)

    def lookup(self, name, client, principal):
        """Returns FSObject associated with name in the dir"""
        log_o.log(5, "ConfigObj.lookup(%r, %r)" % (name, principal))
        entries = self._build_entries(client)
        id = entries.get(name, None)
        if id is None:
            return None
        return self.fs.find(id)

    def readdir(self, verifier, client, principal):
        v0 = "\x00" * 8
        v1 = "\x01" * 8
        if verifier not in (v0, v1):
            raise NFS4Error(NFS4ERR_NOT_SAME)
        entries = self._build_entries(client)
        res = [(name, self.fs.find(id)) for name, id in entries.items()]
        return res, v1

    def _build_entries(self, client):
        def makefh(code, mask=0):
            return code | mask
        def obj_mask(i):
            return (i << 16) | 0x40
        id = self.id
        log_o.log(30, "ConfigObj._build_entries(id=%i, clientid=%i)" % (id, client.clientid))
        if id & 0x40:
            raise NFS4Error(NFS4ERR_NOTDIR)
        cid_mask = (client.clientid << 32) | 0x80
        dir_mask = 0xffffffff

        # BUG - not carefully checking that unused bits are set to 0
        # XXX - actually, exists() needs checking to be lax.  Should
        # have a flag that controls checking, which exists() can set.

        # NOTE XXX - apart from id==1, can't we just compute once and store?
        if id == 1:
            # This is the root
            entries = {"actions"   : makefh(8),
                       "serverwide": makefh(2),
                       "perclient" : makefh(3, cid_mask),
                       "ops"       : makefh(4),
                       }
        elif id == 8:
            # This is actions dir
            entries = {}
            for i, attr in enumerate(self.fs.server.actions.attrs):
                entries[attr.name] = 8 | obj_mask(i)
        elif id == 2:
            # This is serverwide dir
            entries = {}
            for i, attr in enumerate(self.fs.server.config.attrs):
                entries[attr.name] = 2 | obj_mask(i)
        elif id & dir_mask == 3 | 0x80:
            # This is perclient dir
            entries = {}
            for i, attr in enumerate(client.config.attrs):
                entries[attr.name] = 3 | cid_mask | obj_mask(i)
        elif id == 4:
            # This is ops/serverwide dir
            entries = {}
            for i, attr in enumerate(self.fs.server.opsconfig.attrs):
                entries[attr.name] = 4 | obj_mask(i)
        else:
            raise RuntimeError("Called readdir with id=%i" % id)
        return entries

class ConfigFS(FileSystem):
    def __init__(self, server, fsid=0):
        self._nextid = 0
        FileSystem.__init__(self, objclass= ConfigObj)
        self.server = server
        self.fsid = (4, fsid)

    def delegation_options(self):
        # Never grant a delegation, since we want to be able
        # to change objects at will.
        return 0

    def alloc_id(self):
        """Alloc disk space for an FSObject, and return an identifier
        that will allow us to find the disk space later.
        """
        # This should only ever be called to create self.root
        return 1 # linux client BUG - if this is zero, ls "loses" config dir

    def dealloc_id(self, id):
        """Free up disk space associated with id. """
        pass

    def sync(self, obj, how):
        return FILE_SYNC4

    def find_on_disk(self, id):
        """
        id is 64 bits used as follows:
        1-bit obj flag: set means is NF4REG, otherwise is NF4DIR
                        set also means line # is encoded
        1-bit clnt flag: set means clientid is encoded
        6-bit dir code: identifies directory.  If obj flag is set,
                        identifies parent directory.
                        All bits set is reserved to indicate should interpret
                        line # and clientid space differently
        32-bit clientid
        16-bit line #
        8-bit unused for now
        """
        def obj_flag():
            return id & 0x40
        def clnt_flag():
            return id & 0x80
        def dir_code():
            return id & 0x3f
        def line_code():
            return (id & 0xffff0000) >> 16
        def client_code():
            return id >> 32

        dcode = dir_code()
        if dcode == 0x3f:
            raise RuntimeError("Using reserved value")
        if not clnt_flag() and client_code() != 0:
            raise RuntimeError("id=%x" % id)
        if obj_flag():
            # Is an object associated with a configurable attribute
            if dcode == 8:
                # parent == config/actions
                config = self.server.actions
            elif dcode == 2:
                # parent = config/serverwide/
                config = self.server.config
            elif dcode == 3:
                # parent == config/perclient/
                config= self.server.clients[client_code()].config
            elif dcode == 4:
                # parent = config/ops/
                config = self.server.opsconfig
            else:
                raise RuntimeError("id=%x" % id)
            obj = self.objclass(self, id, NF4REG)
            obj.associate(config.attrs[line_code()])
        else:
            # Is a directory.  Tree is currently set up like:
            #                       config (1)
            #        ______________/ /   \  \______________      
            #       /               /     \                \
            # actions (8)   serverwide (2)  perclient (3)  ops (4)
            #
            if line_code() != 0:
                raise RuntimeError("id=%x" % id)
            # We don't have to do much here.
            # Directory entries are built on the fly by obj._build_entries()
            obj = self.objclass(self, id)
        obj.refcnt = 1
        return obj

###################################################

import os
import pickle
import shutil
import shelve

class StubFS_Disk(FileSystem):
    _fs_data_name = "fs_info" # DB name where we store persistent data
    def __init__(self, path, reset=False, fsid=None):
        self._nextid = 0
        self.path = path
        self._fs_data = None # The DB itself
        if reset:
            self._reset(path, fsid)
        else:
            self._init(path)
        # XXX Note shelve DB is still open

    def _reset(self, path, fsid):
        """Create an empty fs, overwriting all existing data."""
        # Check path exists
        if not os.path.exists(path):
            os.makedirs(path) # XXX restrict mode?
        if not os.path.isdir(path):
            raise RuntimeError
        # Ensure path is empty
        shutil.rmtree(path)
        os.makedirs(path)
        # This needs to be open before calling __init__
        d = self._fs_data = shelve.open(os.path.join(path, self._fs_data_name),
                                        "n")
        d["_nextid"] = self._nextid
        # normal __init__
        FileSystem.__init__(self)
        self.fsid = (3, fsid)
        self.sync(self.root, FILE_SYNC4)
        # Write persistent fs data
        d["root"] = self.root.id
        d["fsid"] = self.fsid
        for attr in dir(self):
            if attr.startswith("fattr4_") and not hasattr(self.__class__, attr):
                d[attr] = getattr(self, attr)
        d.sync()

    def _init(self, path):
        """Represent an existing on-disk fs"""
        # Check path exists
        if not os.path.isdir(path):
            raise RuntimeError("Path doesn't exist, try using '--reset' option")
        # Ensure persistent fs data exists there
        d = self._fs_data = shelve.open(os.path.join(path, self._fs_data_name),
                                        "w") # w needed for later allocation
        # Do __init__ portion that is needed
        self.objclass = FSObject
        self._disk_lock = Lock("FSLock(Disk)")
        self.read_only = False
        self._ids = {} # {obj.id: obj}

        # Copy persistent data
        self._fs_data = d
        for attr in d:
            setattr(self, attr, d[attr])

        # Read in root data
        self.root = self.find(d["root"])

    def find_on_disk(self, id):
        fd = open(os.path.join(self.path, "m_%i" % id), "r")
        # BUG - need to trap for file not found error
        meta = pickle.load(fd)
        fd.close()
        obj = self.objclass(self, id, meta)
        if obj.type == NF4REG:
            fd = open(os.path.join(self.path, "d_%i" % id), "r")
            obj.file = StringIO(fd.read())
            fd.close()
        elif obj.type == NF4DIR:
            fd = open(os.path.join(self.path, "d_%i" % id), "r")
            obj.entries = pickle.load(fd)
            fd.close()
        return obj

    def alloc_id(self):
        """Alloc disk space for an FSObject, and return an identifier
        that will allow us to find the disk space later.
        """
        self._disk_lock.acquire()
        try:
            # Get id
            self._nextid += 1
            id = self._nextid
            self._fs_data["_nextid"] = id
            self._fs_data.sync()
            # Create meta-data file
            fd = open(os.path.join(self.path, "m_%i" % id), "w")
            fd.close()
            # Create data file
            # fd = open(os.path.join(self.path, "d_%i" % id), "w")
            # fd.close()
        finally:
            self._disk_lock.release()
        return id

    def dealloc_id(self, id):
        """Free up disk space associated with id. """
        self._disk_lock.acquire()
        try:
            # Remove meta-data file
            meta = os.path.join(self.path, "m_%i" % id)
            if os.path.isfile(meta):
                os.remove(meta)
            # Remove data file
            data = os.path.join(self.path, "d_%i" % id)
            if os.path.isfile(data):
                os.remove(data)
        finally:
            self._disk_lock.release()

    def sync(self, obj, how):
        log_fs.log(5, "DISK.sync()")
        id = obj.id
        self._disk_lock.acquire()
        try:
            # Create meta-data file
            log_fs.debug("writing metadata for id=%i" % id)
            fd = open(os.path.join(self.path, "m_%i" % id), "w")
            log_fs.debug("%r" % obj.meta.__dict__)
            pickle.dump(obj.meta, fd)
            fd.close()
            if obj.type == NF4REG:
                # Create data file
                fd = open(os.path.join(self.path, "d_%i" % id), "w")
                obj.file.seek(0)
                fd.write(obj.file.read())
                fd.close()
            elif obj.type == NF4DIR:
                # Create dir entries
                log_fs.debug("writing dir %r" % obj.entries.keys())
                fd = open(os.path.join(self.path, "d_%i" % id), "w")
                pickle.dump(obj.entries, fd)
                fd.close()
        finally:
            self._disk_lock.release()
        return FILE_SYNC4

###################################################

from pnfs_block_type import pnfs_block_extent4, pnfs_block_layout4
import block

class my_ro_extent(object):
    def __init__(self, f_offset, d_offset, length):
        if d_offset is None:
            self.d_offset = 0
            self.state = block.PNFS_BLOCK_NONE_DATA
        else:
            self.d_offset = d_offset # in blocks
            self.state = block.PNFS_BLOCK_READ_DATA
            self.state = block.PNFS_BLOCK_READWRITE_DATA
        self.length = length # in blocks
        self.f_offset = f_offset # in blocks

class my_rw_extent(object):
    def __init__(self, f_offset, d_offset, length, type):
        if type is None:
            self.state = block.PNFS_BLOCK_INVALID_DATA
        else:
            self.state = block.PNFS_BLOCK_READWRITE_DATA
        self.length = length # in blocks
        self.d_offset = d_offset # in blocks
        self.f_offset = f_offset # in blocks

E = my_ro_extent
EW = my_rw_extent

test_layout_dict = {
    1 : [E(0, 1, 6)], # 1-4 simplest possible layout
    2 : [E(0,9,2), E(2,7, 2)], # 5-8 split into two extents
    3 : [E(0,11, 2), E(2,None, 2), E(4,13, 2)], # 9-12 with a hole in the center
    4 : [E(0,16, 1), E(1,15, 1), None, E(2,18, 1), E(3,17, 1)], # 13-16 partial layout
    }

class LayoutFSObj(FSObject):
    def _get_layout(self, arg):
        # QQQ
        try:
            raw = test_layout_dict[self.id]
        except KeyError:
            raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)
        bs = self.fs.fattr4_layout_blksize
        if not raw:
            file_end = -1
        else:
            file_end = raw[-1].length + raw[-1].f_offset - 1
        if 0: #self.id in (1,2,3,4):
            # These are read-only
            if arg.loga_iomode != LAYOUTIOMODE4_READ:
                raise NFS4Error(NFS4ERR_BADIOMODE, tag="Read-only file")
        else:
            end_request = arg.loga_offset + arg.loga_length
            end_request /= bs
            if file_end < end_request:
                # Need to allocate more blocks sectors
                # count = min(end_request - file_end, 4)
                count = end_request - file_end
                if arg.loga_length == 0xffffffffffffffff:
                    count = min(count, 4)
                block_offset = self.fs._alloc_blocks(count)
                if not raw or raw[-1].state != block.PNFS_BLOCK_INVALID_DATA:
                    raw.append(EW(file_end + 1, block_offset, count, None))
                else:
                    raw[-1].length += count
                # file_end = end_request
                file_end += count

        # STUB - for the moment, ignore args.
        # We just expand raw and return that
        id = self.fs.volume.devid
        file_offset = 0
        elist = []
        for e in raw:
            if e is None:
                # STUB - want to break up layout here
                continue
            length = e.length * bs
            disk_offset = e.d_offset * bs
            file_offset = e.f_offset * bs
            elist.append(pnfs_block_extent4(id, file_offset, length,
                                            disk_offset,
                                            e.state))
        block_layout = pnfs_block_layout4(elist)
        print block_layout
        p = block.Packer()
        p.pack_pnfs_block_layout4(block_layout)
##         if self.id <= 4:
##             mode = LAYOUTIOMODE4_READ
        if 0:
            pass
        else:
            mode = LAYOUTIOMODE4_RW
        self.current_layout = (arg.loga_layout_type, 0, file_end+1, mode)
        return layout4(0, (file_end+1)*bs, mode,
                       layout_content4(arg.loga_layout_type, p.get_buffer()))

    def _commit_layout(self, arg):
        type, l_start, l_len, x = self.current_layout
        if type != arg.loca_layoutupdate.lou_type:
            raise  NFS4Error(NFS4ERR_BADLAYOUT, tag="Commiting a non-block layout")
        bs = self.fs.fattr4_layout_blksize
        if arg.loca_offset % bs or arg.loca_length % bs:
            raise NFS4Error(NFS4ERR_BADLAYOUT, tag="Bad alignment in commit")
        start = arg.loca_offset / bs
        length = arg.loca_length / bs
        if start < l_start or l_start + l_len < start + length:
            raise NFS4Error(NFS4ERR_BADLAYOUT, tag="Commit outside of layout range")
        try:
            raw = test_layout_dict[self.id]
        except KeyError:
            # This shouldn't happen, given that we checked current_layout
            raise NFS4Error(NFS4ERR_LAYOUTUNAVAILABLE)
        if not arg.loca_layoutupdate.lou_body:
            upd_list = []
        else:
            p = block.Unpacker(arg.loca_layoutupdate.lou_body)
            try:
                update = p.unpack_pnfs_block_layoutupdate4()
                p.done()
            except:
                log_o.exception("Problem decoding opaque")
                raise NFS4Error(NFS4ERR_BADLAYOUT, tag="Error decoding opaque")
            upd_list = update.blu_commit_list
            print upd_list
        # Error check
        for e in upd_list:
            if e.bex_state != block.PNFS_BLOCK_READWRITE_DATA:
                raise NFS4Error(NFS4ERR_BADLAYOUT, tag="update.es != READ_WRITE_DATA")
            if e.bex_storage_offset % bs or e.bex_length % bs or e.bex_file_offset % bs:
                raise NFS4Error(NFS4ERR_BADLAYOUT, tag="update extent not aligned")
            if e.bex_file_offset/bs < start or start + length  < (e.bex_file_offset + e.bex_length) / bs:
                raise NFS4Error(NFS4ERR_BADLAYOUT, tag="update extent outside committed range")
        # Modify layout
        for e in upd_list:
            e_start = e.bex_file_offset / bs
            e_len = e.bex_length / bs
            e_off = e.bex_storage_offset / bs
            for ri, le in enumerate(reversed(raw)):
                if e_start >= le.f_offset:
                    break
            i = len(raw) - 1 - ri
            # le==raw[i] now points to my_rw_extent that should be split
            # check update block-file mapping
            if e_start - le.f_offset != e_off - le.d_offset:
                raise NFS4Error(NFS4ERR_BADLAYOUT, tag="mapping inconsitent in update extent %i (le.f_off=%i, le.d_off=%i, %i, %i)" % (i, le.f_offset, le.d_offset, e_start, e_off))
            replace = []
            if e_start > le.f_offset:
                # Need prepend INVAL
                replace.append(EW(le.f_offset, le.d_offset, e_start - le.f_offset, None))
            # Add READ_WRITE
            replace.append(EW(e_start, e_off, e_len, 1))
            if e_start + e_len < le.f_offset + le.length:
                # Need append INVAL
                replace.append(EW(e_start + e_len, e_off + e_len,le.f_offset + le.length - (  e_start + e_len), None))
            raw[i:i+1] = replace
        # Set attrs
        new_size = arg.loca_last_write_offset + 1
        if new_size > self.fattr4_size:
            self.fattr4_size = new_size
            return new_size
        else:
            return None

    def read(self, offset, count, principal): # NF4REG only
        # STUB - need to acces scsi device - for now just return poison
        return ("poisoned" * (count >> 3))[0:count]
        self.file.seek(offset)
        data = self.file.read(count)
        self.change_access()
        return data

    def _getsize(self):
        # STUB
        return self._size

    def _setsize(self, value):
        if self.fattr4_type == NF4REG:
            if value == self.fattr4_size:
                return
            else:
                # STUB There are probably paddding/truncation issues here
                self._size = value
                self.change_data()
        else:
            raise NFS4Error(NFS4ERR_INVAL)

    def _init_hook(self):
        self._size = 0

    fattr4_size = property(_getsize, _setsize)

class Device(object):
    """Not used, but store here visible API being developed for backing_device.
    """
    def __init__(self):
        self.address_body = "" # opaque part of device_addr4
        self.devid = None # deviceid4, set by server

class BlockLayoutFS(FileSystem):
    """Exports a filesystem using block layout protocol.

    This is all a huge STUB.
    """
    def __init__(self, fsid, backing_device):
        # STUB - need some way to specify layout
        self._nextid = 0
        FileSystem.__init__(self, objclass=LayoutFSObj)
        self.fsid = (3, fsid)
        self.fattr4_fs_layout_type = [LAYOUT4_BLOCK_VOLUME]
        self.fattr4_supported_attrs |= 1 << FATTR4_FS_LAYOUT_TYPES
        self.fattr4_layout_blksize = 4096
        self.fattr4_supported_attrs |= 1 << FATTR4_LAYOUT_BLKSIZE
        self.fattr4_maxwrite = 4096
        self.fattr4_maxread = 4096
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXWRITE
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXREAD
        self.volume = backing_device # of type BlockVolume for now
        self._make_files(backing_device)
        self._allocated = 19

    def _make_files(self, dev):
        # STUB - hard code some test files with various properties
        
        # These will use test_layout_dict to get id to layout mapping
        princ = nfs4lib.NFS4Principal("root", system=True)
        bs = self.fattr4_layout_blksize
        self.root.create("simple_extent", princ, NF4REG, {FATTR4_SIZE: int(3.5*bs)})
        self.root.create("split_extent", princ, NF4REG, {FATTR4_SIZE: int(3.5*bs)})
        self.root.create("hole_between_extents", princ, NF4REG, {FATTR4_SIZE: int(5.5*bs)})
        self.root.create("partial_layout", princ, NF4REG, {FATTR4_SIZE: int(3.5*bs)})
        # Fill data blocks
        self._mark_blocks(dev, range(1, 19))
        self._mark_files(dev)
        # raise RuntimeError

    def _mark_blocks(self, dev, blocks):
        bs = self.fattr4_layout_blksize
        # STUB - use 'with'
        fd = dev.open()
        for b in blocks:
            fd.seek(b * bs)
            fd.write(chr(65 + b%26) * bs) # Fill block with a letter
            fd.seek(b * bs)
            fd.write("Start of block %i  " % b)
            endtext = "  block %i ends here -->*" % b
            end_offset = len(endtext)
            fd.seek((b + 1) * bs - end_offset)
            fd.write(endtext)
        fd.close()

    def _mark_files(self, dev):
        bs = self.fattr4_layout_blksize
        fd = dev.open()
        text = "  file ends here -->*"
        offset = len(text)
        for where in [4.5, 8.5, 14.5, 17.5]:
            fd.seek(int(bs*where) - offset)
            fd.write(text)
        fd.close()

    def attach_to_server(self, server):
        server.assign_deviceid(self.volume)

    def alloc_id(self):
        rv = self._nextid
        self._nextid += 1
        if rv > 4:
            test_layout_dict[rv] = []
        return rv

    def _alloc_blocks(self, count):
        # This needs to be lock protected
        rv = self._allocated
        self._allocated += count
        return rv

    def dealloc_id(self, id):
        pass

    def sync(self, obj, how):
        return FILE_SYNC4

    def delegation_options(self):
        # Never grant a delegation, since we don't want to deal with
        # conflicts with layouts
        return 0

    def layout_options(self):
        return LAYOUT4_BLOCK_VOLUME

    def get_devicelist(self, kind, verf):
        """Returns list of deviceid's of type kind, using verf for caching."""
        # STUB - not dealing with verf caching
        if kind != LAYOUT4_BLOCK_VOLUME:
            return []
        return [self.volume]

class FSLayoutFSObj(FSObject):
    def _get_layout(self, arg):
        """Needs to support striping
        """
        # STUB: make nflutil a control variable
        nflutil = self.stripe_size
        # STUB: Return the layout_content4 for pnfs-files
        # This works only with one device id
        id = self.fs.dsdevice.devid
        fhs = self.fs.dsdevice.get_ds_filehandles(self.fh)
        file_layout = nfsv4_1_file_layout4(id, nflutil, 0, 0, fhs)
        p = NFS4Packer()
        p.pack_nfsv4_1_file_layout4(file_layout)

        # STUB: we ony support whole file RW layouts for the moment
        # as it facilitates commits, returns, recalls etc.
        l_offset = 0
        l_len = NFS4_UINT64_MAX
        # use requested iomode
        l_mode = arg.loga_iomode
        l_type = LAYOUT4_NFSV4_1_FILES
        self.current_layout = (l_type, l_offset, l_len, l_mode)
        return layout4(l_offset, l_len, l_mode,
                       layout_content4(l_type, p.get_buffer()))

    def _commit_layout(self, arg):
        # STUB:
        if not arg.loca_last_write_offset.no_newoffset:
            return None
        new_sz = arg.loca_last_write_offset.no_offset + 1
        if new_sz >= self.fattr4_size:
            # Note cannot set fattr4_size here, as that will
            # zero out everything.  Here, since we are using FileLayoutFile,
            # we know that truncate will just set size without touching data
            self.file.truncate(new_sz)
            return new_sz
        return None

    def init_file(self):
        self.stripe_size = NFL4_UFLG_STRIPE_UNIT_SIZE_MASK & 0x4000
        if self.fs.dsdevice.mdsds:
            return StringIO()
        else:
            return FileLayoutFile(self)

    def layout_open_hook(self):
        self.fs.dsdevice.open_ds_file(mds_fh=self.fh)

    def layout_close_hook(self):
        self.fs.dsdevice.close_ds_file(mds_fh=self.fh)

class FileLayoutFS(FileSystem):
    """Exports a filesystem using a simple file layout pfs protocol
    """
    def __init__(self, fsid, dsdevice):
        self._nextid = 0
        self.dsdevice = dsdevice
        FileSystem.__init__(self, objclass=FSLayoutFSObj)
        self.fsid = (2, fsid)
        self.fattr4_fs_layout_type = [LAYOUT4_NFSV4_1_FILES]
        self.fattr4_supported_attrs |= 1 << FATTR4_FS_LAYOUT_TYPES
        self.fattr4_maxwrite = 8192
        self.fattr4_maxread = 8192
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXWRITE
        self.fattr4_supported_attrs |= 1 << FATTR4_MAXREAD
        self.sync(self.root, FILE_SYNC4)

    def attach_to_server(self, server):
        server.assign_deviceid(self.dsdevice)

    def alloc_id(self):
        """Alloc disk space for an FSObject, and return an identifier
        that will allow us to find the disk space later.
        """
        self._nextid += 1
        return self._nextid

    def dealloc_id(self, id):
        """Free up disk space associated with id. """
        return

    def sync(self, obj, how):
        return FILE_SYNC4

    def delegation_options(self):
        # Never grant a delegation, since we don't want to deal with
        # conflicts with layouts
        return 0

    def layout_options(self):
        return LAYOUT4_NFSV4_1_FILES

    def get_devicelist(self, kind, verf):
        raise NotImplementedError

class FileLayoutFile(object): # XXX This should inherit from fs_base.py
    """Emulate the file object by passing data through MDS to DS"""
    def __init__(self, obj):
        self._size = 0
        self._pos = 0
        self._obj = obj

    def __len__(self):
        self._size = self._query_size()
        return self._size

    def seek(self, offset, whence=0):
        # Find new pos
        if whence == 0: # From file start
            newpos = offset
        elif whence == 1: # Relative to pos
            newpos = self._pos + offset
        elif whence == 2: # Relative to end
            self._size = self._query_size()
            newpos = self._size + offset
        self._pos = newpos

    def tell(self):
        return self._pos

    def read(self, count=None):
        out = []
        self._size = self._query_size()
        bytes_to_read = max(0, self._size - self._pos)
        # Note count < 0 is equiv to count == None
        if count is not None and count >= 0:
            bytes_to_read = min(bytes_to_read, count)
        while bytes_to_read:
            vol, v_pos, length = self._find_extent(self._pos)
            limit = min(length, bytes_to_read)
            vol.seek(v_pos)
            segment = vol.read(limit)
            bytes = len(segment)
            if bytes == 0:
                break
            out.append(segment)
            self._pos += len(segment)
            bytes_to_read -= len(segment)
        return ''.join(out)

    def _query_size(self):
        size = self._size
        for ds in self._obj.fs.dsdevice.list:
            vol = FilelayoutVolWrapper(self._obj, ds)
            size = max(size, vol.get_size())
        return size

    def _create_hole(self, offset, length):
        while length:
            vol, v_pos, v_len = self._find_extent(offset)
            vol.seek(v_pos)
            v_len = min(v_len, length)
            v_len = min(v_len, 8192) # Don't overwhelm MDS/DS channel limits
            vol.write('\0' * v_len)
            length -= v_len

    def write(self, data):
        self._size = self._query_size()
        if data and self._pos > self._size:
            self._create_hole(self._size, self._pos - self._size)
        while data:
            vol, v_pos, length = self._find_extent(self._pos)
            length = min(length, 8192) # Don't overwhelm MDS/DS channel limits
            vol.seek(v_pos)
            segment = data[:length]
            # Need to deal with short writes
            vol.write(segment)
            self._pos += len(segment)
            data = data[length:]
        self._size = max(self._size, self._pos)

    def truncate(self, size=None):
        if size is None:
            size = self._pos
        self._size = size
        device = self._obj.fs.dsdevice
        for vol in device.list:
            FilelayoutVolWrapper(self._obj, vol).truncate(size)

    def _find_extent(self, file_offset):
        """Given file offset, return matching volume and vol_offset.

        In addition, return length for which that mapping is valid.
        """
        device = self._obj.fs.dsdevice
        stripe = self._obj.stripe_size
        count = len(device.list)
        v_pos = file_offset
        index = (file_offset // stripe) % count
        remaining = stripe - (file_offset % stripe)
        vol = FilelayoutVolWrapper(self._obj, device.list[index])
        return vol, v_pos, remaining

import nfs4_ops as op

class FilelayoutVolWrapper(object):
    def __init__(self, obj, dataserver):
        self._obj = obj
        self._ds = dataserver
        self._fh = dataserver.filehandles[obj.fh][0]
        self._pos = 0

    def read(self, count):
        # STUB stateid0 is illegal to a ds
        ops = [op.putfh(self._fh),
               op.read(nfs4lib.state00, self._pos, count)]
        # There are all sorts of error handling issues here
        res = self._ds.execute(ops)
        data = res.resarray[-1].data
        self._pos += len(data)
        return data

    def seek(self, offset):
        self._pos = offset

    def write(self, data):
        ops = [op.putfh(self._fh),
               op.write(nfs4lib.state00, self._pos, FILE_SYNC4, data)]
        # There are all sorts of error handling issues here
        res = self._ds.execute(ops)
        self._pos += len(data)
        return

    def truncate(self, size):
        ops = [op.putfh(self._fh),
               op.setattr(nfs4lib.state00, {FATTR4_SIZE: size})]
        res = self._ds.execute(ops)
        return

    def get_size(self):
        ops = [op.putfh(self._fh),
               op.getattr(1L << FATTR4_SIZE)]
        res = self._ds.execute(ops)
        attrdict = res.resarray[-1].obj_attributes
        return attrdict.get(FATTR4_SIZE, 0)

################################################

"""
A new object is created via a call to obj.create, which calls:
  fs.create, newobj.set_attrs, oldobj.link

fs.create calls:
  id = fs.alloc_id()
  obj = Object(id)
"""
