from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import nfs_client_id4, clientaddr4, cb_client4
from .environment import check
import os
import threading
import time
import nfs_ops
op = nfs_ops.NFS4ops()

_lock = threading.Lock()

class _handle_error(object):
    def __init__(self, c, res, ops):
        self.c = c
        self.res = res
        self.ops = ops
        
    def run(self):
        if self.res.status != NFS4_OK:
            time.sleep(2)
            _lock.acquire()
            try:
                self.c.compound(ops)
            except Exception as e:
                print("CALLBACK error in _recall:", e)
                pass
            _lock.release()
            
def _recall(c, thisop, cbid):
    # Note this will be run in the cb_server thread, not the tester thread
    ops = [op.putfh(thisop.opcbrecall.fh),
           op.delegreturn(thisop.opcbrecall.stateid)]
    _lock.acquire()
    try:
        res = c.compound(ops)
    except Exception as e:
        print("CALLBACK error in _recall:", e)
        res = None
    _lock.release()
    if res is not None and res.status != NFS4_OK:
        t_error = _handle_error(c, res, ops)
        t = threading.Thread(target=t_error.run)
        t.setDaemon(1)
        t.start()
    return res

def _cause_recall(t, env):
    c = env.c2
    c.init_connection()
    sleeptime = 1
    while 1:
        # need lock around this to prevent _recall from
        # calling c.unpacker.reset while open is still unpacking
        _lock.acquire()
        res = c.open_file(b'newowner', c.homedir + [t.word()],
                          access=OPEN4_SHARE_ACCESS_WRITE,
                          deny=OPEN4_SHARE_DENY_NONE)
        _lock.release()
        if res.status == NFS4_OK: break
        check(res, [NFS4_OK, NFS4ERR_DELAY], "Open which causes recall")
        env.sleep(sleeptime, 'Got NFS4ERR_DELAY on open')
    return c.confirm(b'newowner', res)

def _verify_cb_occurred(t, c, count):
    newcount = c.cb_server.opcounts[OP_CB_RECALL]
    if newcount <= count:
        t.fail("Recall for callback_ident=%i never occurred" % c.cbid)
    res = c.cb_server.get_recall_res(c.cbid)
    if res is not None:
        check(res, msg="DELEGRETURN")

def _get_deleg(t, c, path, funct=None, response=NFS4_OK, write=False,
               deny=OPEN4_SHARE_DENY_NONE):
    time.sleep(0.5) # Give server time to check callback path
    if write:
        access = OPEN4_SHARE_ACCESS_WRITE
        deleg = OPEN_DELEGATE_WRITE
        name = "write delegation"
    else:
        access = OPEN4_SHARE_ACCESS_READ
        deleg = OPEN_DELEGATE_READ
        name = "read delegation"
    # Create the file
    res = c.create_file(t.word(), path, access=access, deny=deny, 
                        set_recall=True, attrs={FATTR4_MODE: 0o666},
                        recall_funct=funct, recall_return=response)
    check(res)
    fh, stateid = c.confirm(t.word(), res)
    # Check for delegation
    deleg_info = res.resarray[-2].switch.switch.delegation
    if deleg_info.delegation_type == deleg:
        return deleg_info, fh, stateid
    
    # Try opening the file again
    res = c.open_file(t.word(), path, access=access, deny=deny, 
                      set_recall=True,
                      recall_funct=funct, recall_return=response)
    check(res)
    fh, stateid = c.confirm(t.word(), res)
    deleg_info = res.resarray[-2].switch.switch.delegation
    if deleg_info.delegation_type != deleg:
        t.pass_warn("Could not get %s" % name)
    return deleg_info, fh, stateid

def _read_deleg(t, env, funct=None, response=NFS4_OK):
    """Get and recall a read delegation

    The cb_server will first call funct, then respond with response
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], funct, response)
    _cause_recall(t, env)
    _verify_cb_occurred(t, c, count)

def _write_deleg(t, env, funct=None, response=NFS4_OK):
    """Get and recall a read delegation

    The cb_server will first call funct, then respond with response
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], funct, response, write=True)
    _cause_recall(t, env)
    _verify_cb_occurred(t, c, count)

####################################################

def testReadDeleg1(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG1
    """
    _read_deleg(t, env, _recall)

def testReadDeleg2(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return OK, but client never sends DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG2
    """
    _read_deleg(t, env)

def testReadDeleg3a(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: delegations
    CODE: DELEG3a
    """
    _read_deleg(t, env, None, NFS4ERR_RESOURCE)

def testReadDeleg3b(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: delegations
    CODE: DELEG3b
    """
    _read_deleg(t, env, None, NFS4ERR_SERVERFAULT)

def testReadDeleg3c(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: delegations
    CODE: DELEG3c
    """
    _read_deleg(t, env, None, NFS4ERR_BADXDR)

def testReadDeleg3d(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: delegations
    CODE: DELEG3d
    """
    _read_deleg(t, env, None, NFS4ERR_BAD_STATEID)

def testReadDeleg3e(t, env):
    """DELEGATION test

    Get read delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: delegations
    CODE: DELEG3e
    """
    _read_deleg(t, env, None, NFS4ERR_BADHANDLE)

def testCloseDeleg(t, env, funct=_recall, response=NFS4_OK):
    """Get a read delegation, close the file, then recall

    Get read delegation, close the file, then have conflicting open recall it.
    Respond properly and send DELEGRETURN.

    (The cb_server will first call funct, then respond with response)

    FLAGS: delegations
    CODE: DELEG4
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    
    deleg_info, fh, stateid = _get_deleg(t, c, c.homedir + [t.word()],
                                         funct, response)
    res = c.close_file(t.word(), fh, stateid)
    check(res, msg="Closing a file with a delegation held")
    _cause_recall(t, env)
    _verify_cb_occurred(t, c, count)

def testManyReaddeleg(t, env, funct=_recall, response=NFS4_OK):
    """Width test - recall many read delegations at once

    Get many read delegation, then have conflicting open recall them.
    Respond properly and send DELEGRETURN for each.

    (The cb_server will first call funct, then respond with response)

    FLAGS: delegations
    CODE: DELEG5
    """
    # XXX needs to use _get_deleg
    count = 100 # Number of read delegations to grab
    c = env.c1
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    cbids = []
    fh, stateid = c.create_confirm(t.word(), access=OPEN4_SHARE_ACCESS_READ,
                                   deny=OPEN4_SHARE_DENY_NONE,
                                   attrs={FATTR4_MODE: 0o666})
    for i in range(count):
        c.init_connection(b'pynfs%i_%s_%i' % (os.getpid(), t.word(), i), cb_ident=0)
        fh, stateid = c.open_confirm(t.word(), access=OPEN4_SHARE_ACCESS_READ,
                                     deny=OPEN4_SHARE_DENY_NONE)
            
        # Get a read delegation
        res = c.open_file(t.word(), access=OPEN4_SHARE_ACCESS_READ,
                          deny=OPEN4_SHARE_DENY_NONE,
                          set_recall=True,
                          recall_funct=funct, recall_return=response)
        fh, stateid = c.confirm(t.word(), res)
        deleg_info = res.resarray[-2].switch.switch.delegation
        if deleg_info.delegation_type == OPEN_DELEGATE_READ:
            cbids.append(c.cbid)
    if not cbids:
        t.pass_warn("Could not get any read delegations")
    print("Got %i out of %i read delegations" % (len(cbids), count))
    # Cause them to be recalled
    fh2, stateid2 = _cause_recall(t, env)
    miss_count = 0
    for id in cbids:
        res = c.cb_server.get_recall_res(id)
        if res is None:
            miss_count += 1
        else:
            check(res, msg="DELEGRETURN for cb_id=%i" % id)
    if miss_count:
        t.pass_warn("Recall never occurred for %i of %i read delegations" %
                    (miss_count, len(cbids)))

def testRenew(t, env, funct=None, response=NFS4_OK):
    """Get and recall a read delegation

    The cb_server will first call funct, then respond with response
    FLAGS: delegations
    CODE: DELEG6
    """
    c = env.c1
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    lease = c.getLeaseTime()
    deleg_info, fh, stateid = _get_deleg(t, c, c.homedir + [t.word()], funct, response)
    c2 = env.c2
    c2.init_connection()
    try:
        c.cb_command(0) # Shut off callback server
        noticed = False
        for i in range(4):
            res = c2.open_file(b'newowner', c.homedir + [t.word()],
                              access=OPEN4_SHARE_ACCESS_WRITE)
            env.sleep(lease / 2, "Waiting to send RENEW")
            res = c.compound([op.renew(c.clientid)])
            check(res, [NFS4_OK, NFS4ERR_CB_PATH_DOWN], "RENEW")
            if res.status != NFS4_OK:
                noticed = True
                break
    finally:
        c.cb_command(1) # Turn on callback server
    res = c.compound([op.putfh(fh), op.delegreturn(deleg_info.read.stateid)])
    check(res)
    res = c.close_file(t.word(), fh, stateid)
    check(res)
    if not noticed:
        t.fail("RENEWs should not have all returned OK")

def testIgnoreDeleg(t, env, funct=_recall, response=NFS4_OK):
    """Get a read delegation, and ignore it, then recall

    Get read delegation, close the file, then do more open/closes/locks.
    Finally have conflicting open recall it.
    Respond properly and send DELEGRETURN.

    (The cb_server will first call funct, then respond with response)

    FLAGS: delegations
    CODE: DELEG7
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    path = c.homedir + [t.word()]
    deleg_info, fh, stateid = _get_deleg(t, c, path, funct, response)

    # Close the file
    res = c.close_file(t.word(), fh, stateid)
    check(res, msg="Closing a file with a delegation held")

    # Play with file some more
    fh, stateid = c.open_confirm(b"NaughtyOwner", path,
                                 access=OPEN4_SHARE_ACCESS_READ,
                                 deny=OPEN4_SHARE_DENY_NONE)
    res = c.lock_file(b"NaughtyOwner", fh, stateid, type=READ_LT)
    check(res)
    fh2, stateid2 = c.open_confirm(t.word(), access=OPEN4_SHARE_ACCESS_READ,
                                   deny=OPEN4_SHARE_DENY_NONE)
    res = c.unlock_file(1, fh, res.lockid)
    check(res)
    
    # Cause it to be recalled
    _cause_recall(t, env)
    _verify_cb_occurred(t, c, count)


def testDelegShare(t, env, funct=_recall, response=NFS4_OK):
    """Get a read delegation with share_deny_write, then try to recall

    Get read delegation with share_deny_write, then see if a conflicting
    write open recalls the delegation (it shouldn't).

    FLAGS: delegations
    CODE: DELEG8
    """
    c = env.c1
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], funct, response,
               deny=OPEN4_SHARE_DENY_WRITE)

    # Try conflicting write open
    sleeptime = 5
    while 1:
        # need lock around this to prevent _recall from
        # calling c.unpacker.reset while open is still unpacking
        _lock.acquire()
        res = c.open_file(b'newowner', c.homedir + [t.word()],
                          access=OPEN4_SHARE_ACCESS_WRITE)
        _lock.release()
        if res.status in  [NFS4_OK, NFS4ERR_SHARE_DENIED]: break
        check(res, [NFS4_OK, NFS4ERR_DELAY, NFS4ERR_SHARE_DENIED],
                  "Open which causes recall")
        env.sleep(sleeptime, 'Got NFS4ERR_DELAY on open')
        sleeptime += 5
        if sleeptime > 20:
            sleeptime = 20
    check(res, NFS4ERR_SHARE_DENIED)

    # Verify cb did NOT occur
    if funct is not None:
        res = c.cb_server.get_recall_res(c.cbid)
        if res is not None:
            t.fail("Recall for callback_ident=%i occurred" % c.cbid)

def _set_clientid(c, id, server):
    client_id = nfs_client_id4(c.verifier, id)
    r_addr = c.ipaddress + server.dotport
    cb_location = clientaddr4(b'tcp', r_addr)
    callback = cb_client4(server.prog, cb_location)
    return op.setclientid(client_id, callback, 1)

def testChangeDeleg(t, env, funct=_recall):
    """Get a read delegation, change to a different callback server, then
    recall the delegation

    FLAGS: delegations
    CODE: DELEG9
    """
    from nfs4lib import CBServer
    c = env.c1
    id = b'pynfs%i_%s' % (os.getpid(), t.word())
    c.init_connection(id, cb_ident=0)
    deleg_info, fh, stateid = _get_deleg(t, c, c.homedir + [t.word()], funct, NFS4_OK)
    # Create new callback server
    new_server = CBServer(c)
    new_server.set_cb_recall(c.cbid, funct, NFS4_OK);
    cb_thread = threading.Thread(target=new_server.run)
    cb_thread.setDaemon(1)
    cb_thread.start()
    c.cb_server = new_server
    env.sleep(3)
    # Switch to using new server
    res = c.compound([_set_clientid(c, id, new_server)])
    check(res, msg="Switch to new callback server")
    c.clientid = res.resarray[0].switch.switch.clientid
    confirm = res.resarray[0].switch.switch.setclientid_confirm
    confirmop = op.setclientid_confirm(c.clientid, confirm)
    res = c.compound([confirmop])
    check(res, [NFS4_OK, NFS4ERR_RESOURCE])
    if res.status == NFS4ERR_RESOURCE:
        # ibm workaround
        res = c.compound([confirmop])
        check(res)
    count = new_server.opcounts[OP_CB_RECALL]
    fh2, stateid2 = _cause_recall(t, env)
    _verify_cb_occurred(t, c, count)


   
    
###################################

def testWriteDeleg1(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Respond properly and send DELEGRETURN.

    FLAGS: writedelegations
    CODE: DELEG11
    """
    _write_deleg(t, env, _recall)

def testWriteDeleg2(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return OK, but client never sends DELEGRETURN.

    FLAGS: writedelegations
    CODE: DELEG12
    """
    _write_deleg(t, env)

def testWriteDeleg3a(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: writedelegations
    CODE: DELEG13a
    """
    _write_deleg(t, env, None, NFS4ERR_RESOURCE)

def testWriteDeleg3b(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: writedelegations
    CODE: DELEG13b
    """
    _write_deleg(t, env, None, NFS4ERR_SERVERFAULT)

def testWriteDeleg3c(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: writedelegations
    CODE: DELEG13c
    """
    _write_deleg(t, env, None, NFS4ERR_BADXDR)

def testWriteDeleg3d(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: writedelegations
    CODE: DELEG13d
    """
    _write_deleg(t, env, None, NFS4ERR_BAD_STATEID)

def testWriteDeleg3e(t, env):
    """DELEGATION test

    Get write delegation, then have conflicting open recall it.
    Have callback server return error.

    FLAGS: writedelegations
    CODE: DELEG13e
    """
    _write_deleg(t, env, None, NFS4ERR_BADHANDLE)

def testClaimCur(t, env):
    """DELEGATION test

    Get read delegation, then have it recalled.  In the process
    of returning, send some OPENs with CLAIM_DELEGATE_CUR

    FLAGS: delegations
    CODE: DELEG14
    """
    c = env.c1
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    
    deleg_info, fh, stateid = _get_deleg(t, c, c.homedir + [t.word()],
                                         None, NFS4_OK)
    
    # Cause it to be recalled, and wait for cb_recall to finish
    # FRED - this is problematic if server doesn't reply until
    # it gets the DELEGRETURN
    c2 = env.c2
    c2.init_connection()
    res = c2.open_file(b'newowner', c.homedir + [t.word()],
                      access=OPEN4_SHARE_ACCESS_WRITE,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, [NFS4_OK, NFS4ERR_DELAY], "Open which causes recall")
    env.sleep(2, "Waiting for recall")

    # Now send some opens
    path = c.homedir + [t.word()]
    res = c.open_file(b'owner1', path, access=OPEN4_SHARE_ACCESS_READ,
                            claim_type=CLAIM_DELEGATE_CUR,
                            deleg_stateid=deleg_info.read.stateid)
    check(res)
    ops = c.use_obj(path) + [op.delegreturn(deleg_info.read.stateid)]
    res = c.compound(ops)
    check(res)

def _retry_conflicting_op(env, c, op, opname):
    while 1:
        _lock.acquire()
        res = c.compound(op)
        _lock.release()
        if res.status == NFS4_OK: break
        check(res, [NFS4_OK, NFS4ERR_DELAY],
                            "%s which causes recall" % opname)
        env.sleep(1, 'Got NFS4ERR_DELAY on %s' % opname)
                            
def testRemove(t, env):
    """DELEGATION test

    Get read delegation, then ensure REMOVE recalls it.
    Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG15a
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    ops = c.use_obj(c.homedir) + [op.remove(t.word())]
    _retry_conflicting_op(env, c, ops, "remove")
    _verify_cb_occurred(t, c, count)

def testLink(t, env):
    """DELEGATION test

    Get read delegation, then ensure LINK recalls it.
    Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG15b
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    ops = c.use_obj(c.homedir + [t.word()]) + [op.savefh()];
    ops += c.use_obj(c.homedir) + [op.link(t.word() + b'.link')];
    _retry_conflicting_op(env, c, ops, "link")
    _verify_cb_occurred(t, c, count)

def testRename(t, env):
    """DELEGATION test

    Get read delegation, then ensure RENAME recalls it.
    Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG15c
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    ops = c.use_obj(c.homedir) + [op.savefh()];
    ops += c.use_obj(c.homedir) + [op.rename(t.word(), t.word() + b'.rename')]
    _retry_conflicting_op(env, c, ops, "rename")
    _verify_cb_occurred(t, c, count)

def testRenameOver(t, env):
    """DELEGATION test

    Get read delegation, then ensure RENAME of other file over it recalls it.
    Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG15d
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    res = c.create_file(t.word(), c.homedir + [t.word()])
    _get_deleg(t, c, c.homedir + [t.word() + b'.rename'], _recall, NFS4_OK)
    ops = c.use_obj(c.homedir) + [op.savefh()];
    ops += c.use_obj(c.homedir) + [op.rename(t.word(), t.word() + b'.rename')]
    _retry_conflicting_op(env, c, ops, "rename")
    _verify_cb_occurred(t, c, count)

def _listToPath(components):
    return b'/'+b'/'.join(components)

def testServerRemove(t, env):
    """DELEGATION test

    Get read delegation, then ensure removing the file on the server
    recalls it.  Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG16
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    env.serverhelper(b"unlink " + _listToPath(c.homedir + [t.word()]))
    _verify_cb_occurred(t, c, count)

def testServerRenameSource(t, env):
    """DELEGATION test

    Get read delegation, then ensure renaming the file on the server
    recalls it.  Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG17
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    env.serverhelper(b"rename " + _listToPath(c.homedir + [t.word()]) + b" "
                               + _listToPath(c.homedir + [t.word() + b"-2"]))
    _verify_cb_occurred(t, c, count)


def testServerRenameTarget(t, env):
    """DELEGATION test

    Get read delegation, then ensure renaming over the file on the server
    recalls it.  Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG18
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    c.create_confirm(t.word(), path=c.homedir + [t.word() + b'-2'])
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    env.serverhelper(b"rename " + _listToPath(c.homedir + [t.word() + b"-2"])
                                + b" "
                                + _listToPath(c.homedir + [t.word()]))
    _verify_cb_occurred(t, c, count)

def testServerLink(t, env):
    """DELEGATION test

    Get read delegation, then ensure adding a link to the file on the server
    recalls it.  Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG19
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    c.create_confirm(t.word(), path=c.homedir + [t.word() + b'-2'])
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    env.serverhelper(b"link " + _listToPath(c.homedir + [t.word()]) + b" "
                               + _listToPath(c.homedir + [t.word() + b"-link"]))
    _verify_cb_occurred(t, c, count)

def testServerChmod(t, env):
    """DELEGATION test

    Get read delegation, then ensure changing mode bits on the server
    recalls it.  Respond properly and send DELEGRETURN.

    FLAGS: delegations
    CODE: DELEG20
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    c.create_confirm(t.word(), path=c.homedir + [t.word() + b'-2'])
    _get_deleg(t, c, c.homedir + [t.word()], _recall, NFS4_OK)
    env.serverhelper(b"chmod 0777 " + _listToPath(c.homedir + [t.word()]))
    _verify_cb_occurred(t, c, count)

def testServerSelfConflict(t, env):
    """DELEGATION test

    Get a read delegation, then do a write open from the same client.
    It should not conflict with the read delegation.

    FLAGS: delegations
    CODE: DELEG21
    """
    c = env.c1
    count = c.cb_server.opcounts[OP_CB_RECALL]
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    deleg_info, fh, stateid = _get_deleg(t, c, c.homedir + [t.word()], None, NFS4_OK)

    sleeptime = 1
    while 1:
        # need lock around this to prevent _recall from
        # calling c.unpacker.reset while open is still unpacking
        _lock.acquire()
        res = c.open_file(b'newowner', c.homedir + [t.word()],
                          access=OPEN4_SHARE_ACCESS_WRITE,
                          deny=OPEN4_SHARE_DENY_NONE)
        _lock.release()
        if res.status == NFS4_OK: break
        check(res, [NFS4_OK, NFS4ERR_DELAY], "Open which causes recall")
        env.sleep(sleeptime, 'Got NFS4ERR_DELAY on open')
    c.confirm(b'newowner', res)
    res = c.compound([op.putfh(fh), op.delegreturn(deleg_info.read.stateid)])
    check(res)
    res = c.close_file(t.word(), fh, stateid)
    check(res)
    newcount = c.cb_server.opcounts[OP_CB_RECALL]
    if newcount > count:
        t.fail("Unnecessary delegation recall")

def testServerSelfConflict2(t,env):
    """DELEGATION test

    Test that we can still get a delegation even when we have the
    file open for write from the same client.

    FLAGS: delegations
    CODE: DELEG22
    """
    c = env.c1
    c.init_connection(b'pynfs%i_%s' % (os.getpid(), t.word()), cb_ident=0)
    time.sleep(0.5)
    res = c.create_file(t.word(), c.homedir+[t.word()],
                        access = OPEN4_SHARE_ACCESS_BOTH,
                        deny = OPEN4_SHARE_DENY_NONE)
    check(res)
    fh, stateid = c.confirm(t.word(), res)
    deleg_info = res.resarray[-2].switch.switch.delegation
    if deleg_info.delegation_type != OPEN_DELEGATE_NONE:
        return
    res = c.open_file(t.word(), c.homedir+[t.word()],
                        access=OPEN4_SHARE_ACCESS_BOTH,
                        deny = OPEN4_SHARE_DENY_NONE)
    check(res)
    fh, stateid = c.confirm(t.word(), res)
    deleg_info = res.resarray[-2].switch.switch.delegation
    if deleg_info.delegation_type == OPEN_DELEGATE_NONE:
        t.fail("Could not get delegation")
