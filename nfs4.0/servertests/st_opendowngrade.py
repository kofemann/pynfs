from nfs4_const import *
from environment import check, makeStaleId

def testRegularOpen(t, env):
    """OPENDOWNGRADE on regular file

    FLAGS: opendowngrade all
    DEPEND: MKFILE
    CODE: OPDG1
    """
    c = env.c1
    c.init_connection()
    c.create_confirm(t.code, access=OPEN4_SHARE_ACCESS_READ,
                     deny=OPEN4_SHARE_DENY_NONE)
    fh, stateid = c.open_confirm(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                                 deny=OPEN4_SHARE_DENY_NONE)
    res = c.downgrade_file(t.code, fh, stateid, OPEN4_SHARE_ACCESS_READ,
                           deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="OPENDOWNGRADE on regular file")

def testNewState1(t, env):
    """OPENDOWNGRADE to never opened mode should return NFS4ERR_INVAL

    FLAGS: opendowngrade all
    DEPEND: MKFILE
    CODE: OPDG2
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_NONE)
    res = c.downgrade_file(t.code, fh, stateid, OPEN4_SHARE_ACCESS_READ,
                           deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE to never opened mode")

def testNewState2(t, env):
    """OPENDOWNGRADE to never opened mode should return NFS4ERR_INVAL

    FLAGS: opendowngrade all
    DEPEND: MKFILE
    CODE: OPDG3
    """
    c = env.c1
    c.init_connection()
    c.create_confirm(t.code, access=OPEN4_SHARE_ACCESS_WRITE,
                     deny=OPEN4_SHARE_DENY_NONE)
    fh, stateid = c.open_confirm(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                                 deny=OPEN4_SHARE_DENY_NONE)
    res = c.downgrade_file(t.code, fh, stateid, OPEN4_SHARE_ACCESS_READ,
                           deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE to never opened mode")

def testBadSeqid(t, env):
    """OPENDOWNGRADE with bad seqid should return NFS4ERR_BAD_SEQID

    FLAGS: opendowngrade seqid all
    DEPEND: MKFILE
    CODE: OPDG4
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, fh, stateid, seqid=50)
    check(res, NFS4ERR_BAD_SEQID, "OPENDOWNGRADE with bad seqid=50")
    
def testBadStateid(t, env):
    """OPENDOWNGRADE with bad stateid should return NFS4ERR_BAD_STATEID

    FLAGS: opendowngrade badid all
    DEPEND: MKFILE
    CODE: OPDG5
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, fh, env.stateid0)
    check(res, NFS4ERR_BAD_STATEID, "OPENDOWNGRADE with bad stateid")

def testStaleStateid(t, env):
    """OPENDOWNGRADE with stale stateid should return NFS4ERR_STALE_STATEID

    FLAGS: opendowngrade staleid all
    DEPEND: MKFILE
    CODE: OPDG6
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, fh, makeStaleId(stateid))
    check(res, NFS4ERR_STALE_STATEID, "OPENDOWNGRADE with stale stateid")

def testOldStateid(t, env):
    """OPENDOWNGRADE with old stateid should return NFS4ERR_OLD_STATEID

    FLAGS: opendowngrade oldid all
    DEPEND: MKFILE
    CODE: OPDG7
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.code)
    check(res, msg="Creating file %s" % t.code)
    oldstateid = res.resarray[-2].switch.switch.stateid
    fh, stateid = c.confirm(t.code, res)
    res = c.downgrade_file(t.code, fh, oldstateid)
    check(res, NFS4ERR_OLD_STATEID, "OPENDOWNGRADE with old stateid")

def testNoFh(t, env):
    """OPENDOWNGRADE with no (cfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: opendowngrade emptyfh all
    DEPEND: MKFILE
    CODE: OPDG8
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, None, stateid)
    check(res, NFS4ERR_NOFILEHANDLE, "OPENDOWNGRADE with no <cfh>")

def testDir(t, env):
    """OPENDOWNGRADE using dir

    FLAGS: opendowngrade dir all
    DEPEND: MKFILE LOOKDIR
    CODE: OPDG9d
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.usedir, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])
    
def testLink(t, env):
    """OPENDOWNGRADE using non-file object

    FLAGS: opendowngrade symlink all
    DEPEND: MKFILE LOOKLINK
    CODE: OPDG9a
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.uselink, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])
    
def testBlock(t, env):
    """OPENDOWNGRADE using non-file object

    FLAGS: opendowngrade block all
    DEPEND: MKFILE LOOKBLK
    CODE: OPDG9b
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.useblock, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])
    
def testChar(t, env):
    """OPENDOWNGRADE using non-file object

    FLAGS: opendowngrade char all
    DEPEND: MKFILE LOOKCHAR
    CODE: OPDG9c
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.usechar, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])
    
def testFifo(t, env):
    """OPENDOWNGRADE using non-file object

    FLAGS: opendowngrade fifo all
    DEPEND: MKFILE LOOKFIFO
    CODE: OPDG9f
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.usefifo, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])
    
def testSocket(t, env):
    """OPENDOWNGRADE using non-file object

    FLAGS: opendowngrade socket all
    DEPEND: MKFILE LOOKSOCK
    CODE: OPDG9s
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.downgrade_file(t.code, env.opts.usesocket, stateid)
    check(res, NFS4ERR_INVAL, "OPENDOWNGRADE with nonfile object",
          [NFS4ERR_BAD_STATEID])

class open_sequence:
    def __init__(self, client, owner):
	self.client = client
        self.owner = owner
    def open(self, access):
	self.fh, self.stateid = self.client.create_confirm(self.owner,
						access=access,
						deny=OPEN4_SHARE_DENY_NONE,
						mode=UNCHECKED4)
    def downgrade(self, access):
	res = self.client.downgrade_file(self.owner, self.fh, self.stateid,
					access=access,
					deny=OPEN4_SHARE_DENY_NONE)
	self.stateid = res.stateid
    def close(self):
	self.client.close_file(self.owner, self.fh, self.stateid)

def testOpenDowngradeSequence(t, env):
    """test complex upgrade/downgrade sequence

    FLAGS: opendowngrade all
    DEPEND: MKFILE
    CODE:OPDG10
    """
    c = env.c1
    c.init_connection()
    os = open_sequence(c, t.code)
    os.open(     OPEN4_SHARE_ACCESS_READ)
    os.open(     OPEN4_SHARE_ACCESS_WRITE)
    os.downgrade(OPEN4_SHARE_ACCESS_READ)
    os.open(     OPEN4_SHARE_ACCESS_WRITE)
    os.downgrade(OPEN4_SHARE_ACCESS_READ)
    os.open(     OPEN4_SHARE_ACCESS_WRITE)
    os.downgrade(OPEN4_SHARE_ACCESS_WRITE)
    os.open(     OPEN4_SHARE_ACCESS_READ)
    os.close()

def list_os(state, depth):
    if depth == 0:
        return (("c",),)
    # try each possible open:
    s = ()
    for i in [0, 1, 2]:
        if state[i] == 0:
            s += tuple(map(lambda x: ("o%s"%(["r", "w", "b"][i]),) + x,
                    list_os(state[0:i] + (1,) + state[i:3], depth-1)))
    if sum(state) <= 1:
        # no downgrades are possible:
        return s
    if state[0] == 1:
        # read downgrade:
        s += tuple(map(lambda x: ("dr",) + x,
                    list_os((1, 0, 0), depth - 1)))
    if state[1] == 1:
        # write downgrade:
        s += tuple(map(lambda x: ("dw",) + x,
                    list_os((0, 1, 0), depth - 1)))
    return s

def list_open_sequences(depth):
    return list_os((0,0,0), depth)

def testOpenDowngradeSequences(t, env):
    """test complex upgrade/downgrade sequences

    FLAGS: opendowngrade all
    DEPEND: MKFILE
    CODE:OPDG11
    """

    c = env.c1
    c.init_connection()
    os = open_sequence(c, t.code)
    sequences = list_open_sequences(5)

    for s in sequences:
        for command in s:
            if command == "close":
                os.close()
            elif command == "or":
                os.open(OPEN4_SHARE_ACCESS_READ)
            elif command == "ow":
                os.open(OPEN4_SHARE_ACCESS_WRITE)
            elif command == "ob":
                os.open(OPEN4_SHARE_ACCESS_BOTH)
            elif command == "dr":
                os.downgrade(OPEN4_SHARE_ACCESS_READ)
            elif command == "dw":
                os.downgrade(OPEN4_SHARE_ACCESS_WRITE)
