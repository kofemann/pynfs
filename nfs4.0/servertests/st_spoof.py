from xdrdef.nfs4_const import *
from .environment import check

def testSpoofUser(t, env):
    """SPOOF test, try to spoof user
    Use options --usefile, --uid, and --gid
    Indicated file will be read and over-written.

    FLAGS: spoof
    CODE: SPOOF1
    """

    c = env.c1
    path = env.opts.usefile
    c.init_connection()
    fh, stateid = c.open_confirm(t.word(), path, access=OPEN4_SHARE_ACCESS_READ)
    res = c.read_file(fh, 5, 1000, stateid)
    check(res, msg="Reading file /%s" % '/'.join(path))
    res = c.close_file(t.word(), fh, stateid)
    check(res, msg="CLOSE a non-create open")
    fh, stateid = c.open_confirm(t.word(), path, access=OPEN4_SHARE_ACCESS_WRITE)
    res = c.write_file(fh, "random text to write", 50, stateid, FILE_SYNC4)
    check(res, msg="WRITE with openstateid and FILE_SYNC4")
    res = c.close_file(t.word(), fh, stateid)
    check(res, msg="CLOSE a non-create open")
    

"""
How get fh's?
  exported but illegal to access files
  non-exported files on same partition
"""
def testSpoofFhRead(t, env):
    r"""SPOOF test, try to spoof fh
    Use option --usefh="\xhh\xhh\xhh...", where hh is a pair of hex digits.
    
    FLAGS: spoof
    CODE: SPOOF2
    """
    c = env.c1
    c.init_connection()
    path = _convert(env.opts.usefh)
    res = c.read_file(path) # Uses 0 stateid
    check(res, msg="Reading fh %r" % path)
       
def testSpoofFhWrite(t, env):
    """SPOOF test, try to spoof fh

    FLAGS: spoof
    CODE: SPOOF3
    """
    c = env.c1
    c.init_connection()
    path = _convert(env.opts.usefh)
    res = c.write_file(path, "random text to write", 50)
    check(res)
       
def _convert(str):
    out = ""
    i = 0
    
    while i < len(str):
        if str[i] == '\\':
            c = chr(eval("0x%s" % str[i+2:i+4]))
            i += 4
        else:
            c = str[i]
            i += 1
        out += c
    return out
