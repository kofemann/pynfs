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

# NOTE: retired test codes, please do not reuse:
# OPDG9a
# OPDG9b
# OPDG9c
# OPDG9d
# OPDG9f
# OPDG9s

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
    def lock(self, type):
        self.client.lock_file(self.owner, self.fh, self.stateid,
                    type=type)
	

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

def testOpenDowngradeLock(t, env):
    """Try open, lock, open, downgrade, close

    FLAGS: opendowngrade all lock
    CODE: OPDG11
    """
    c= env.c1
    c.init_connection()
    os = open_sequence(c, t.code)
    os.open(OPEN4_SHARE_ACCESS_BOTH)
    os.lock(READ_LT)
    os.open(OPEN4_SHARE_ACCESS_READ)
    os.downgrade(OPEN4_SHARE_ACCESS_READ)
    os.close()
