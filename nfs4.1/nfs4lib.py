from __future__ import with_statement
import rpc
import nfs4_const
import nfs4_pack
import nfs4_type
import nfs4_ops as op
import time
import collections
import hmac
import struct
import random
import re
from locking import Lock
try:
    from Crypto.Cipher import AES
except ImportError:
    class AES(object):
        """Create a fake class to use as a placeholder.

        This will give an error only if actually used.
        """
        MODE_CBC = 0
        def new(self, *args, **kwargs):
            raise NotImplementedError("could not import Crypto.Cipher")

# Special stateids
state00 = nfs4_type.stateid4(0, "\0" * 12)
state11 = nfs4_type.stateid4(0xffffffff, "\xff" * 12)
state01 = nfs4_type.stateid4(1, "\0" * 12)

import hashlib # Note this requires 2.5 or higher

# Note that all the oid strings have tag and length bytes prepended, as
# per description of sec_oid4 in draft26 sect 3.2

# The strings are oid values derived from RFC4055 section 2.1
# sha1   : 1.3.14.3.2.26
# sha256 : 2.16.840.1.101.3.4.2.4.1
# sha384 : 2.16.840.1.101.3.4.2.4.2
# sha512 : 2.16.840.1.101.3.4.2.4.3
# sha224 : 2.16.840.1.101.3.4.2.4.4
hash_oids = {"sha1"   : '\x06\x05\x2b\x0e\x03\x02\x1a',
             "sha256" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01',
             "sha384" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02',
             "sha512" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03',
             "sha224" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04',
             }
hash_algs = {hash_oids["sha1"]   : hashlib.sha1,
             hash_oids["sha256"] : hashlib.sha256,
             hash_oids["sha384"] : hashlib.sha384,
             hash_oids["sha512"] : hashlib.sha512,
             hash_oids["sha224"] : hashlib.sha224,
             }

class _e_wrap(object):
    """Wrap encryption algs so they have a consistent interface"""
    block_size = property(lambda s: s._block_size)
    key_size = property(lambda s: s._key_size)

    def __init__(self, factory, key_size, block_size=0, mode=0):
        self._factory = factory
        self._key_size = key_size
        self._block_size = block_size
        self._mode = mode

    def new(self, key, **kwargs):
        if len(key) != self._key_size:
            raise "Some error here" # STUB
        kwargs["mode"] = self._mode
        return self._factory.new(key, **kwargs)

# These strings are oid values derived from data found at
# <http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/isop.html> and
# <http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html>
# aes128-CBC : 2.16.840.1.101.3.4.1.2
# aes192-CBC : 2.16.840.1.101.3.4.1.22
# aes256-CBC : 2.16.840.1.101.3.4.1.42
encrypt_oids = {"aes128-CBC" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02',
                "aes192-CBC" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x16',
                "aes256-CBC" : '\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2a',
                }
encrypt_algs = {encrypt_oids["aes128-CBC"] : _e_wrap(AES, 16, 16, AES.MODE_CBC),
                encrypt_oids["aes192-CBC"] : _e_wrap(AES, 24, 16, AES.MODE_CBC),
                encrypt_oids["aes256-CBC"] : _e_wrap(AES, 32, 16, AES.MODE_CBC),
                }

# Defined in draft26 sect 2.10.9 as 1.3.6.1.4.1.28882.1.1
ssv_mech_oid = '\x06\x0a\x2b\x06\x01\x04\x01\x81\xe1\x52\x01\x01'

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

def printhex(str, pretty=True):
    """Print string as hex digits"""
    if pretty:
        print "".join(["%02x " % ord(c) for c in str])
    else:
        # Can copy/paste this string
        print "".join(["\\x%02x" % ord(c) for c in str])

def str_xor(a, b):
    """xor two string which represent binary data"""
    # Note assumes they are the same length
    # XXX There has to be a library function somewhere that does this
    return ''.join(map(lambda x:chr(ord(x[0])^ord(x[1])), zip(a, b)))

def random_string(size):
    """Returns a random string of given length."""
    return "".join([chr(random.randint(0, 255)) for i in xrange(size)])

class SSVContext(object):
    """Holds algorithms and keys needed for SSV encryption and hashing"""
    class SSVName(object):
        def __init__(self, name):
            self.name = name

    def __init__(self, hash_funct, encrypt_factory, window, client=True):
        self.source_name = self.SSVName("SSV Stub name")
        self.hash = hash_funct
        self.encrypt = encrypt_factory
        self.window = window
        self.local = client # True for client, False for server
        self.ssv_len = hash_funct().digest_size
        self.ssvs = collections.deque()
        self.ssv_seq = 0 # This basically counts the number of SET_SSV calls
        self.lock = Lock("ssv")
        # Per draft 26:
        # "Before SET_SSV is called the first time on a client ID,
        # the SSV is zero"
        self._add_ssv('\0' * self.ssv_len)

    def _subkey(self, ssv, i):
        """Generate subkeys as defined in draft26 2.10.9"""
        if i == 0:
            return ssv
        else:
            return hmac.new(ssv, struct.pack('>L', i), self.hash).digest()

    def _add_ssv(self, ssv):
        """Adds the literal string ssv and its associated subkeys"""
        # Lock held by caller
        keys = [self._subkey(ssv, i) for i in range(5)]
        self.ssvs.appendleft(keys)
        if len(self.ssvs) > self.window:
            self.ssvs.pop()

    def set_ssv(self, ssv):
        """Handles the state management of SET_SSV call, XORing for new ssv."""
        with self.lock:
            new_ssv = str_xor(ssv, self.ssvs[0][0])
            self._add_ssv(new_ssv)
            self.ssv_seq += 1 # draft26 18.47.3

    def hmac(self, data, key_index):
        return hmac.new(self.ssvs[0][key_index], data, self.hash).digest()

    def _computeMIC(self, data, key, seqnum):
        """Compute getMIC token from given data"""
        # See draft26 2.10.9
        p = FancyNFS4Packer()
        p.pack_ssv_mic_plain_tkn4(nfs4_type.ssv_mic_plain_tkn4(seqnum, data))
        hash = hmac.new(key, p.get_buffer(), self.hash).digest()
        p.reset()
        p.pack_ssv_mic_tkn4(nfs4_type.ssv_mic_tkn4(seqnum, hash))
        return p.get_buffer()

    def getMIC(self, data):
        dir = (SSV4_SUBKEY_MIC_I2T if self.local else SSV4_SUBKEY_MIC_T2I)
        with self.lock:
            seqnum = self.ssv_seq
            key = self.ssvs[0][dir]
        return self._computeMIC(data, key, seqnum)

    def verifyMIC(self, data, checksum):
        p = FancyNFS4Unpacker(checksum)
        try:
            token = p.unpack_ssv_mic_tkn4()
            p.done()
        except:
            raise "Need error here" # STUB
        if token.smt_ssv_seq == 0:
            raise "Need error here" # STUB
        dir = (SSV4_SUBKEY_MIC_T2I if self.local else SSV4_SUBKEY_MIC_I2T)
        with self.lock:
            index = self.ssv_seq - token.smt_ssv_seq
            try:
                key = self.ssvs[index][dir]
            except KeyError:
                raise "Need error here" # STUB
        expect = self._computeMIC(data, key, token.smt_ssv_seq)
        if expect != checksum:
            raise "Need error here" # STUB
        return 0 # default qop

    def wrap(self, data):
        """Compute wrap token from given data"""
        # See draft26 2.10.9
        with self.lock:
            keys = self.ssvs[0]
            seqnum = self.ssv_seq
        blocksize = self.encrypt.block_size
        cofounder = random_string(4) # '4' pulled out of nowhere
        p = FancyNFS4Packer()
        # We need to compute pad.  Easiest (though not fastest) way
        # is to pack w/o padding, determine padding needed, then repack.
        input = nfs4_type.ssv_seal_plain_tkn4(cofounder, seqnum, data, "")
        p.pack_ssv_seal_plain_tkn4(input)
        offset = len(p.get_buffer()) % blocksize
        if offset:
            pad = '\0' * (blocksize - offset)
            p.reset()
            input = nfs4_type.ssv_seal_plain_tkn4(cofounder, seqnum, data, pad)
            p.pack_ssv_seal_plain_tkn4(input)
        plain_xdr = p.get_buffer()
        p.reset()
        iv = random_string(blocksize)
        dir = (SSV4_SUBKEY_SEAL_I2T if self.local else SSV4_SUBKEY_SEAL_T2I)
        obj = self.encrypt.new(keys[dir], IV=iv)
        encrypted = obj.encrypt(plain_xdr)
        dir = (SSV4_SUBKEY_MIC_I2T if self.local else SSV4_SUBKEY_MIC_T2I)
        hash = hmac.new(keys[dir], plain_xdr, self.hash).digest()
        token = nfs4_type.ssv_seal_cipher_tkn4(seqnum, iv, encrypted, hash)
        p.pack_ssv_seal_cipher_tkn4(token)
        return p.get_buffer()

    def unwrap(self, data):
        """Undo the effects of wrap"""
        p = FancyNFS4Unpacker(data)
        try:
            token = p.unpack_ssv_seal_cipher_tkn4()
            p.done()
        except:
            raise "Need error here" # STUB
        if token.ssct_ssv_seq == 0:
            raise "Need error here" # STUB
        with self.lock:
            index = self.ssv_seq - token.ssct_ssv_seq
            try:
                keys = self.ssvs[index]
            except KeyError:
                raise "Need error here" # STUB
        dir = (SSV4_SUBKEY_SEAL_T2I if self.local else SSV4_SUBKEY_SEAL_I2T)
        obj = self.encrypt.new(keys[dir], IV=token.ssct_iv)
        xdr = obj.decrypt(token.ssct_encr_data)
        dir = (SSV4_SUBKEY_MIC_T2I if self.local else SSV4_SUBKEY_MIC_I2T)
        hash = hmac.new(keys[dir], xdr, self.hash).digest()
        if hash != token.ssct_hmac:
            raise "Need error here" # STUB
        p.reset(xdr)
        try:
            plain = p.unpack_ssv_seal_plain_tkn4()
            p.done()
        except:
            raise "Need error here" # STUB
        if plain.sspt_ssv_seq != token.ssct_ssv_seq:
            raise "Need error here" # STUB
        return plain.sspt_orig_plain, 0

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

        path = m.group('path')
        path = (path_components(path) if path else [])

        return tuple(server_list), path
    else:
        raise ValueError("Error parsing NFS URL: %s" % url)

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

class NFS4Principal(object):
    """Encodes information needed to determine access rights."""
    def __init__(self, name, system=False):
        self.name = name
        self.skip_checks = system

    def member_of(self, group):
        """Returns True if self.name is a memeber of given group."""
        # STUB
        return False

    def __str__(self):
        return self.name

    def __eq__(self, other):
        # STUB - ignores mappings
        return self.name == other.name

    def __ne__(self, other):
        return not self.__eq__(other)

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

def use_obj(file):
    """File is either None, a fh, or a list of path components"""
    if file is None or file == [None]:
        return []
    elif type(file) is str:
        return [op.putfh(file)]
    else:
        return [op.putrootfh()] + [op.lookup(comp) for comp in file]

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
              FATTR4_FS_LAYOUT_TYPES : A("r", "fs"),
              FATTR4_LAYOUT_HINT : A("w", "obj"),
              FATTR4_LAYOUT_TYPES : A("r", "obj"),
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
