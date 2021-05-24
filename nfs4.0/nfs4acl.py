#
# nfs4acl.py - some useful acl code
#
# Written by Fred Isaman <iisaman@citi.umich.edu>
# Copyright (C) 2004 University of Michigan, Center for
#                    Information Technology Integration
#


# Taken from mapping description at
# http://www.citi.umich.edu/projects/nfsv4/rfc/draft-ietf-nfsv4-acl-mapping-02.txt

from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *

# Taken from mapping
MODE_R = ACE4_READ_DATA | ACE4_READ_NAMED_ATTRS
MODE_W = ACE4_WRITE_DATA | ACE4_WRITE_NAMED_ATTRS | ACE4_APPEND_DATA
MODE_X = ACE4_EXECUTE

DMODE_R = ACE4_LIST_DIRECTORY | ACE4_READ_NAMED_ATTRS
DMODE_W = ACE4_ADD_FILE | ACE4_WRITE_NAMED_ATTRS | \
          ACE4_ADD_SUBDIRECTORY | ACE4_DELETE_CHILD
DMODE_X = ACE4_EXECUTE

FLAG_ALL = ACE4_READ_ACL | ACE4_READ_ATTRIBUTES | ACE4_SYNCHRONIZE
FLAG_OWN = ACE4_WRITE_ACL | ACE4_READ_ACL | ACE4_WRITE_ATTRIBUTES
FLAG_NONE = ACE4_DELETE

DDEFAULT = ACE4_INHERIT_ONLY_ACE | ACE4_DIRECTORY_INHERIT_ACE | \
           ACE4_FILE_INHERIT_ACE

# Where is this required?
USED_BITS = 0x1f01ff

# Useful abbreviations
ALLOWED = ACE4_ACCESS_ALLOWED_ACE_TYPE
DENIED = ACE4_ACCESS_DENIED_ACE_TYPE
GROUP = ACE4_IDENTIFIER_GROUP
GROUP_OBJ = ACE4_IDENTIFIER_GROUP # Or is it 0? RFC and map are unclear

MODES = [ 0, MODE_X, MODE_W, MODE_X | MODE_W,
          MODE_R, MODE_R | MODE_X, MODE_R | MODE_W,
          MODE_R | MODE_X | MODE_W ]
DMODES = [ 0, DMODE_X, DMODE_W, DMODE_X | DMODE_W,
           DMODE_R, DMODE_R | DMODE_X, DMODE_R | DMODE_W,
           DMODE_R | DMODE_X | DMODE_W ]

class ACLError(Exception):
    def __init__(self, msg=None):
        if msg is None:
            self.msg = "ACL error"
        else:
            self.msg = str(msg)

    def __str__(self):
        return self.msg

def negate(flags):
    """Return the opposite flags"""
    if flags & ~USED_BITS:
        raise ACLError("Flag %x contains unused bits" % flags)
    return ~flags & USED_BITS & ~FLAG_NONE

def mode2acl(mode, dir=False):
    """Translate a 3-digit octal mode into a posix compatible acl"""
    if dir: modes = DMODES
    else:   modes = MODES
    owner = modes[(mode & 0o700)//0o100] | FLAG_ALL | FLAG_OWN
    group = modes[(mode & 0o070)//0o10] | FLAG_ALL
    other = modes[(mode & 0o007)] | FLAG_ALL

    return [ nfsace4(ALLOWED, 0, owner, "OWNER@"),
             nfsace4(DENIED, 0, negate(owner), "OWNER@"),
             nfsace4(ALLOWED, GROUP_OBJ, group, "GROUP@"),
             nfsace4(DENIED, GROUP_OBJ, negate(group), "GROUP@"),
             nfsace4(ALLOWED, 0, other, "EVERYONE@"),
             nfsace4(DENIED, 0, negate(other), "EVERYONE@")
             ]

def acl2mode(acl):
    """Translate an acl into a 3-digit octal mode"""
    names = ["OWNER@", "GROUP@", "EVERYONE@"]
    short = [ace for ace in acl if ace.who in names]
    perms = dict.fromkeys(names, None)
    modes = [[MODE_R, 4], [MODE_W, 2], [MODE_X, 1]]
    for ace in short:
        if perms[ace.who] is not None: continue
        if ace.type == ALLOWED:
            bits = 0
            for mode, bit in modes:
                if mode & ace.access_mask == mode:
                    bits |= bit
            perms[ace.who] = bits
        elif ace.type == DENIED:
            bits = 7
            for mode, bit in modes:
                if mode & ace.access_mask:
                    bits &= ~bit
            perms[ace.who] = bits
    # If it wasn't mentioned, assume the worse
    for key in perms:
        if perms[key] is None:
            perm[keys] = 0
    return perms["OWNER@"]*0o100 + perms["GROUP@"]*0o10 + perms["EVERYONE@"]

def maps_to_posix(acl):
    """Raises ACLError if acl does not map to posix """

    """ FRED - there are all sorts of things this does not yet check for.
    1 - the mapping allows only certain sets of access_mask
    2 - Only 4 different flags values are allowed
    3 - How to handle mixed default/active on a directory?
    """
    len_acl = len(acl)
    if len_acl < 6:
        raise ACLError("Acl length %i is too short" % len_acl)
    if len_acl > 7 and len_acl%3 != 1:
        raise ACLError("Acl length %i does not equal 1 mod 3" % len_acl)
    flags = acl[0].flag
    if flags != 0: # FIXME and flags != DDEFAULT:
        raise ACLError("Illegal flag value %x" % flags)
    list = acl[:]
    not_mask = chk_owners(list, flags)
    chk_groups(list, flags, not_mask)
    chk_everyone(list, flags)

def chk_pair(allow, deny, who, flags):
    """Checks consistancy of allow/deny pair, forcing it to have given args"""
    if allow.type != ALLOWED or deny.type != DENIED:
        raise ACLError("Wrong type in allow/deny pair")
    if not (flags == allow.flag == deny.flag):
        raise ACLError("Pair does not have required flags %x" % flags)
    if negate(allow.access_mask) != deny.access_mask:
        raise ACLError("Pair access masks %x and %x are not complementary.\n"
                       "Expected inverse of %x is %x." %
                       (allow.access_mask, deny.access_mask,
                        allow.access_mask, negate(allow.access_mask)))
    if not (who == allow.who == deny.who):
        raise ACLError("Pair does not have required who %s" % who)

def chk_triple(mask, allow, deny, flags, not_mask):
    chk_pair(allow, deny, mask.who, flags)
    if mask.type != DENIED:
        raise ACLError("Triple mask does not have type DENIED")
    if flags != mask.flag:
        raise ACLError("Triple mask does not have required flags  %x" % flags)
    if not_mask != mask.access_mask:
        raise ACLError("Triple mask is not same as a previous mask")

def chk_everyone(acl, flags):
    if len(acl) != 2:
        raise ACLError("Had %i ACEs left when called chk_everyone" % len(acl))
    chk_pair(acl[0], acl[1], "EVERYONE@", flags)

def chk_owners(acl, flags):
    chk_pair(acl[0], acl[1], "OWNER@", flags)
    del acl[:2]
    used = []
    not_mask = None
    while True:
        if len(acl) < 3:
            raise ACLError("Ran out of ACEs in chk_owners")
        mask = acl[0]
        if mask.who.endswith("@") or mask.flag & GROUP:
            return not_mask
        if not_mask is None:
            if mask.access_mask & ~USED_BITS:
                raise ACLError("Mask %x contains unused bits" %
                               mask.access_mask)
            not_mask = mask.access_mask
        allow = acl[1]
        deny = acl[2]
        if mask.who in used:
            raise ACLError("Owner name %s duplicated" % mask.who)
        chk_triple(mask, allow, deny, flags, not_mask)
        used.append(mask.who)
        del acl[:3]

def chk_groups(acl, flags, not_mask):
    mask = acl[0]
    if mask.who != "GROUP@":
        raise ACLError("Expected GROUP@, got %s" % mask.who)
    if mask.type == ALLOWED and not_mask is None:
        # Special case of no mask
        chk_pair(acl[0], acl[1], "GROUP@", flags | GROUP_OBJ)
        del acl[:2]
        return
    if not_mask is None:
        if mask.access_mask & ~USED_BITS:
            raise ACLError("Mask %x contains unused bits" % mask.access_mask)
        not_mask = mask.access_mask
    used = ["EVERYONE@"]
    pairs = []
    while mask.who not in used:
        if len(acl) < 3:
            raise ACLError("Ran out of ACEs in chk_groups")
        used.append(mask.who)
        pairs.append([mask, acl[1]])
        del acl[:2]
        mask = acl[0]
    if len(acl) < len(used):
        raise ACLError("Ran out of ACEs in chk_groups")
    for mask, allow in pairs:
        if mask.who == "GROUP@":
            chk_triple(mask, allow, acl[0], flags | GROUP_OBJ, not_mask)
        else:
            chk_triple(mask, allow, acl[0], flags | GROUP, not_mask)
        del acl[:1]

def printableacl(acl):
    type_str = ["ACCESS", "DENY"]
    out = ""
    for ace in acl:
        out += "<type=%6s, flag=%2x, access=%8x, who=%s>\n" % \
               (type_str[ace.type], ace.flag, ace.access_mask, ace.who)
    #print("leaving printableacl with out = %s" % out)
    return out
