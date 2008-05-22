import nfs4_const
import nfs4_pack
import nfs4_type
import time

# Special stateids
state00 = nfs4_type.stateid4(0, "\0" * 12)
state11 = nfs4_type.stateid4(0xffffffff, "\xff" * 12)
state01 = nfs4_type.stateid4(1, "\0" * 12)

import hashlib # Note this requires 2.5 or higher
# The strings are oid values derived from RFC4055
hash_oids = {"sha1" : '+\x0e\x03\x02\x1a',
             "sha256" : '`\x86H\x01e\x03\x04\x02\x01',
             "sha384" : '`\x86H\x01e\x03\x04\x02\x02',
             "sha512" : '`\x86H\x01e\x03\x04\x02\x03',
             "sha224" : '`\x86H\x01e\x03\x04\x02\x04'
             }
hash_algs = {'+\x0e\x03\x02\x1a'          : hashlib.sha1,
             '`\x86H\x01e\x03\x04\x02\x01': hashlib.sha256,
             '`\x86H\x01e\x03\x04\x02\x02': hashlib.sha384,
             '`\x86H\x01e\x03\x04\x02\x03': hashlib.sha512,
             '`\x86H\x01e\x03\x04\x02\x04': hashlib.sha224
             }

# These strings are oid values derived from
# <http://csrc.nist.gov/pki/CSOR/Documents/aes1.asn>
encrypt_oids = {"aes128-CBC" : '`\x86H\x01e\x03\x04\x01\x02',
                "aes192-CBC" : '`\x86H\x01e\x03\x04\x01\x16',
                "aes256-CBC" : '`\x86H\x01e\x03\x04\x01*',
                }

# This is taken from draft-13 section 2.10.7.4 (The SSV GSS Mechanism)
ssv_mech_oid = '+\x06\x01\x04\x01\x81\xe1R\x01\x01'

# Static FATTR4 dictionaries that are created from nfs4_const data
attr2bitnum = {}
bitnum2attr = {}
bitnum2packer = {}
bitnum2unpacker = {}

def set_attrbit_dicts():
    """Set global dictionaries manipulating attribute bit positions.

    Note: This function uses introspection. It assumes an entry
    in nfs4_const.py is an attribute iff it is named FATTR4_<something>. 

    Returns {"type": 1, "fh_expire_type": 2,  "change": 3 ...}
            { 1: "type", 2: "fh_expire_type", 3: "change", ...}
            { 1: "pack_fattr4_type", 2: "pack_fattr4_fh_expire_type", ...}
            { 1: "unpack_fattr4_type", 2: "unpack_fattr4_fh_expire_type", ...}
    """
    global attr2bitnum, bitnum2attr, bitnum2packer, bitnum2unpacker
    for name in dir(nfs4_const):
        if name.startswith("FATTR4_"):
            value = getattr(nfs4_const, name)
            # Sanity checking. Must be integer. 
            assert(type(value) is int)
            attrname = name[7:].lower()
            attr2bitnum[attrname] = value
            bitnum2attr[value] = attrname
            bitnum2packer[value] = "pack_fattr4_%s" % attrname
            bitnum2unpacker[value] = "unpack_fattr4_%s" % attrname
# Actually set the dictionaries
set_attrbit_dicts()

def set_flags(name, search_string=None):
    """Make certain flag lists in nfs4.x easier to deal with.

    Several flags lists in nfs4.x are not enums, which means they are not
    grouped in any way within nfs4_const except by name.  Make a dictionary
    and a cumulative mask called <name>_flags and <name>_mask.  We
    default to using flags of form <NAME>4_FLAG_, unless told otherwise.
    """
    flag_dict = {}
    mask = 0
    if search_string is None:
        search_string = "%s4_FLAG_" % name.upper()
    for var in dir(nfs4_const):
        if var.startswith(search_string):
            value = getattr(nfs4_const, var)
            flag_dict[value] = var
            mask |= value
    # Now we need to set the appropriate module level variable
    d = globals()
    d["%s_flags" % name.lower()] = flag_dict
    d["%s_mask" % name.lower()] = mask

set_flags("exchgid")
set_flags("create_session")
set_flags("access", "ACCESS4_")

class FancyNFS4Packer(nfs4_pack.NFS4Packer):
    """Handle fattr4 and dirlist4 more cleanly than auto-generated methods"""
    def filter_bitmap4(self, data):
        out = []
        while data:
            out.append(data & 0xffffffffL)
            data >>= 32
        return out

    def filter_fattr4(self, data):
        """Allow direct encoding of dict, instead of opaque attrlist"""
        if type(data) is dict:
            data = dict2fattr(data)
        return data

    def filter_dirlist4(self, data):
        """Change simple list of entry4 into strange chain structure"""
        out = []
        for e in data.entries[::-1]:
            # print "handle", e
            # This reverses the direction of the list, so start with reversed
            out = [nfs4_type.entry4(e.cookie, e.name, e.attrs, out)]
        # Must not modify original data structure
        return nfs4_type.dirlist4(out, data.eof)

class FancyNFS4Unpacker(nfs4_pack.NFS4Unpacker):
    def filter_bitmap4(self, data):
        """Put bitmap into single long, instead of array of 32bit chunks"""
        out = 0L
        shift = 0
        for i in data:
            out |= (long(i) << shift)
            shift += 32
        return out

    def filter_fattr4(self, data):
        """Return as dict, instead of opaque attrlist"""
        return fattr2dict(data)

    def filter_dirlist4(self, data):
        """Return as simple list, instead of strange chain structure"""
        chain = data.entries
        list = []
        while chain:
            # Pop first entry off chain
            e = chain[0]
            chain = e.nextentry
            # Add to list
            e.nextentry = None # XXX Do we really want to do this?
            list.append(e)
        data.entries = list
        return data
            
def dict2fattr(dict):
    """Convert a dictionary of form {numb:value} to a fattr4 object.

    Returns a fattr4 object.  
    """

    attrs = dict.keys()
    attrs.sort()

    packer = FancyNFS4Packer()
    attr_vals = ""
    for bitnum in attrs:
        value = dict[bitnum]
        packer.reset()
        getattr(packer, bitnum2packer[bitnum])(value)
        attr_vals += packer.get_buffer()
    attrmask = list2bitmap(attrs)
    return nfs4_type.fattr4(attrmask, attr_vals); 

def fattr2dict(obj):
    """Convert a fattr4 object to a dictionary with attribute name and values.

    Returns a dictionary of form {bitnum:value}
    """
    result = {}
    list = bitmap2list(obj.attrmask)
    unpacker = FancyNFS4Unpacker(obj.attr_vals)
    for bitnum in list:
        result[bitnum] = getattr(unpacker, bitnum2unpacker[bitnum])()
    unpacker.done()
    return result

def list2bitmap(list):
    """Construct a bitmap from a list of bit numbers"""
    mask = 0L
    for bit in list:
        mask |= 1L << bit
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

##########################################################

def test_equal(obj1, obj2, kind="COMPOUND4res"):
    p = FancyNFS4Packer()
    pack = getattr(p, "pack_%s" % kind)
    pack(obj1)
    res1 = p.get_buffer()
    p.reset()
    pack(obj2)
    return res1 == p.get_buffer()

def inc_u32(i):
    """Increment a 32 bit integer, with wrap-around."""
    return int( (i+1) & 0xffffffff )

def dec_u32(i):
    """Decrement a 32 bit integer, with wrap-around."""
    return int( (i-1) & 0xffffffff )

def xdrlen(str):
    """returns length in bytes of xdr encoding of str"""
    return (1 + ((3 + len(str)) >> 2)) << 2

def verify_time(t):
    if t.nseconds >= 1000000000:
        raise NFS4Error(NFS4ERR_INVAL)

def get_nfstime(t=None):
    """Convert time.time() output to nfstime4 format"""
    if t is None:
        t = time.time()
    sec = int(t)
    nsec = int((t - sec) * 1000000000)
    return nfs4_type.nfstime4(sec, nsec)

def path_components(path, use_dots=True):
    """Convert a string '/a/b/c' into an array ['a', 'b', 'c']"""
    out = []
    for c in path.split('/'):
        if c == '':
            pass
        elif use_dots and c == '.':
            pass
        elif use_dots and c == '..':
            del out[-1]
        else:
            out.append(c)
    return out

def attr_name(bitnum):
    """Returns string corresponding to attr bitnum"""
    return bitnum2attr.get(bitnum, "unknown_%r" % bitnum)

class NFS4Error(Exception):
    def __init__(self, status, attrs=0L, lock_denied=None, tag=None, check_msg=None):
        self.status = status
        self.name = nfs4_const.nfsstat4[status]
        if check_msg is None:
            self.msg = "NFS4 error code: %s" % self.name
        else:
            self.msg = check_msg
        self.attrs = attrs
        self.lock_denied = lock_denied
        self.tag = tag

    def __str__(self):
        return self.msg

class NFS4Replay(Exception):
    def __init__(self, cache):
        self.cache = cache

def check(res, expect=nfs4_const.NFS4_OK, msg=None):
    if res.status == expect:
        return
    if type(expect) is str:
        raise RuntimeError("You forgot to put 'msg=' in front "
                           "of check()'s string arg")
    # Get text representations
    desired = nfs4_const.nfsstat4[expect]
    received = nfs4_const.nfsstat4[res.status]
    if msg:
        failedop_name = msg
    elif res.resarray:
        failedop_name = nfs4_const.nfs_opnum4[res.resarray[-1].resop]
    else:
        failedop_name = 'Compound'
    msg = "%s should return %s, instead got %s" % \
          (failedop_name, desired, received)
    raise NFS4Error(res.status, check_msg=msg)

###############################################
# Attribute information
######################################

class AttrConfig(object):
    readable = property(lambda s: s._r)
    writable = property(lambda s: s._w)
    from_obj = property(lambda s: s._f)
    from_fs  = property(lambda s: s._fs)
    from_serv = property(lambda s: s._s)
    def __init__(self, rw, kind="obj"):
        self._r = 'r' in rw
        self._w = 'w' in rw
        self._f = (kind=="obj")
        self._s = (kind=="serv")
        self._fs = (kind=="fs")
    
from nfs4_const import *

A = AttrConfig
attr_info = { FATTR4_SUPPORTED_ATTRS : A("r", "fs"),
              FATTR4_TYPE : A("r", "obj"),
              FATTR4_FH_EXPIRE_TYPE : A("r", "fs"),
              FATTR4_CHANGE : A("r", "obj"),
              FATTR4_SIZE : A("rw", "obj"),
              FATTR4_LINK_SUPPORT : A("r", "fs"),
              FATTR4_SYMLINK_SUPPORT : A("r", "fs"),
              FATTR4_NAMED_ATTR : A("r", "obj"),
              # NOTE we change FSID from "fs" to "obj" to support mounting
              FATTR4_FSID : A("r", "obj"), # QUESTION note error in spec here
              FATTR4_UNIQUE_HANDLES : A("r", "fs"),
              FATTR4_LEASE_TIME : A("r", "serv"),
              FATTR4_RDATTR_ERROR : A("r", "obj"),
              FATTR4_FILEHANDLE : A("r", "obj"),
              FATTR4_SUPPATTR_EXCLCREAT : A("r", "fs"),
              FATTR4_ACL : A("rw", "obj"),
              FATTR4_ACLSUPPORT : A("r", "fs"),
              FATTR4_ARCHIVE : A("rw", "obj"),
              FATTR4_CANSETTIME : A("r", "fs"),
              FATTR4_CASE_INSENSITIVE : A("r", "fs"),
              FATTR4_CASE_PRESERVING : A("r", "fs"),
              FATTR4_CHOWN_RESTRICTED : A("r", "fs"),
              FATTR4_FILEID : A("r", "obj"),
              FATTR4_FILES_AVAIL : A("r", "fs"),
              FATTR4_FILES_FREE : A("r", "fs"),
              FATTR4_FILES_TOTAL : A("r", "fs"),
              FATTR4_FS_LOCATIONS : A("r", "fs"),
              FATTR4_HIDDEN : A("rw", "obj"),
              FATTR4_HOMOGENEOUS : A("r", "fs"),
              FATTR4_MAXFILESIZE : A("r", "fs"),
              FATTR4_MAXLINK : A("r", "fs"), # QUESTION note error in spec
              FATTR4_MAXNAME : A("r", "fs"),
              FATTR4_MAXREAD : A("r", "fs"),
              FATTR4_MAXWRITE : A("r", "fs"),
              FATTR4_MIMETYPE : A("rw", "obj"),
              FATTR4_MODE : A("rw", "obj"),
              FATTR4_NO_TRUNC : A("r", "fs"),
              FATTR4_NUMLINKS : A("r", "obj"),
              FATTR4_OWNER : A("rw", "obj"),
              FATTR4_OWNER_GROUP : A("rw", "obj"),
              FATTR4_QUOTA_AVAIL_HARD : A("r"), # MISS
              FATTR4_QUOTA_AVAIL_SOFT : A("r"), # MISS
              FATTR4_QUOTA_USED : A("r"), # MISS
              FATTR4_RAWDEV : A("r", "obj"),
              FATTR4_SPACE_AVAIL : A("r", "fs"),
              FATTR4_SPACE_FREE : A("r", "fs"),
              FATTR4_SPACE_TOTAL : A("r", "fs"),
              FATTR4_SPACE_USED : A("r", "obj"),
              FATTR4_SYSTEM : A("rw", "obj"),
              FATTR4_TIME_ACCESS : A("r", "obj"),
              FATTR4_TIME_ACCESS_SET : A("w"), # MISS
              FATTR4_TIME_BACKUP : A("rw", "obj"),
              FATTR4_TIME_CREATE : A("rw", "obj"),
              FATTR4_TIME_DELTA : A("r", "fs"),
              FATTR4_TIME_METADATA : A("r", "obj"),
              FATTR4_TIME_MODIFY : A("r", "obj"),
              FATTR4_TIME_MODIFY_SET : A("w"), # MISS
              FATTR4_MOUNTED_ON_FILEID : A("r", "obj"),
              FATTR4_DIR_NOTIF_DELAY : A("r", "obj"),
              FATTR4_DIRENT_NOTIF_DELAY : A("r", "obj"),
              FATTR4_DACL : A("rw", "obj"),
              FATTR4_SACL : A("rw", "obj"),
              FATTR4_CHANGE_POLICY : A("r", "fs"),
              FATTR4_FS_STATUS : A("r", "fs"),
              FATTR4_FS_LAYOUT_TYPE : A("r", "fs"),
              FATTR4_LAYOUT_HINT : A("w", "obj"),
              FATTR4_LAYOUT_TYPE : A("r", "obj"),
              FATTR4_LAYOUT_BLKSIZE : A("r", "fs"),
              FATTR4_LAYOUT_ALIGNMENT : A("r", "obj"),
              FATTR4_FS_LOCATIONS_INFO : A("r", "fs"),
              FATTR4_MDSTHRESHOLD : A("r", "obj"),
              FATTR4_RETENTION_GET : A("r", "obj"),
              FATTR4_RETENTION_SET : A("w", "obj"),
              FATTR4_RETENTEVT_GET : A("r", "obj"),
              FATTR4_RETENTEVT_SET : A("w", "obj"),
              FATTR4_RETENTION_HOLD : A("rw", "obj"),
              FATTR4_MODE_SET_MASKED : A("w", "obj"),
              FATTR4_FS_CHARSET_CAP : A("r", "fs"),
              }
del A
