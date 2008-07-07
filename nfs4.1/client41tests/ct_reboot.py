import os
from environment import fail

def testReboot(t, env):
    """Test reboot

    FLAGS: reboot all
    CODE: REBOOT1
    """
    """
    cd $HOME
    echo "test" >foo
    echo "1" > $ACTIONS/reboot
    cd $ROOT
    cd $HOME
    cat foo
    """
    # cd $HOME
    os.chdir(env.home)
    # echo "test" > foo
    fd = open(env.testname(t), "w")
    data = "test\n"
    fd.write(data)
    fd.close()
    # echo "1" > $ACTIONS/reboot
    env.reboot_server()
    # cd $ROOT
    os.chdir(env.root)
    # cd $HOME
    os.chdir(env.home)
    # cat foo
    fd = open(env.testname(t), "r")
    read = fd.read()
    fd.close()
    if  read != data:
        fail("'cat foo' = %r, expected %r" % (read, data))
    
def testReboot2(t, env):
    """Test v4.1 reboot with no state operation

    FLAGS: reboot all
    CODE: REBOOT2
    """
    """
    cd $HOME
    mkdir testdir
    cd testdir
    mkdir datadir - so that listdir(testdir) only has datadir
    echo "1" > $ACTIONS/reboot
    cd $ROOT  - kick off session recovery for root
    cd $HOME  - kick off session recovery for home
    cd testdir
    listdir(testdir)
    """
    # cd $HOME
    os.chdir(env.home)
    # make a directory to hold the single datadir directory
    testdir = env.testname(t)
    os.mkdir(testdir)
    # cd testsdir
    os.chdir(testdir)
    # make a directory
    datadir = "testit"
    os.mkdir(datadir)
    # echo "test" > foo
    # echo "1" > $ACTIONS/reboot
    env.reboot_server()
    # cd $ROOT
    os.chdir(env.root)
    # cd $HOME
    os.chdir(env.home)
    # read the directory
    read = os.listdir(testdir)
    # cleanup
    os.chdir(testdir)
    os.rmdir(datadir)
    os.chdir(env.home)
    os.rmdir(testdir)
    if  read[0] != datadir:
        fail("'listdir foo' = %r, expected %r" % (read, data))

def testDelegReturn(t, env):
    """Test response to server returning error on DELEGRETURN

    FLAGS: delegreturn all
    CODE: DELEG1
    """
    """
    cd $HOME
    echo "test" > foo
    cat foo # Gives read delegation
    echo "NFS4ERR_RESOURCE" > $CONFIG/ops/perclient/delegreturn
    echo "test2" > foo # recall delegation
    """
    # cd $HOME
    os.chdir(env.home)
    # echo "test" > foo
    foo = env.testname(t)
    fd = open(foo, "w")
    data = "test\n"
    fd.write(data)
    fd.close()
    # cat foo # Will hand out read delegation
    fd = open(foo, "r")
    read = fd.read()
    fd.close()
    # Set delegreturn to return error
    env.set_error("delegreturn", "NFS4ERR_RESOURCE")
    # echo "test2" > foo  # This should cause server to recall delegation
    foo = env.testname(t)
    fd = open(foo, "w")
    data = "test2\n"
    fd.write(data)
    fd.close()
    
def testOpenZeroes(t, env):
    """Test client is zeroing out values on open

    FLAGS: open all
    CODE: OPEN1
    """
    """
    cd $HOME
    touch foo
    """
    foo = env.testname(t)
    env.control_reset()
    # cd $HOME
    os.chdir(env.home)
    # touch foo
    env.control_record(foo)
    fd = open(foo, "w")
    env.control_pause()
    calls = env.control_grab_calls(foo)
    fd.close()
    # Now analyse RPC calls the client made
    for op in env.find_op(OP_OPEN, calls):
        if op.seqid != 0:
            fail("seqid !=0")
        if op.owner.clientid != 0:
            fail("clientid != 0")
        
def testSessionReset(t, env):
    """Test response to server returning NFS4ERR_BADSESSION error on SEQUENCE in OPEN compound

    FLAGS: sequence all
    CODE: SESSIONRESET1
    """
    """
    cd $HOME
    echo "test" >foo
    echo "NFS4ERR_BADSESSION" > $CONFIG/ops/sequence
    cd $ROOT
    cd $HOME
    cat foo
    """
    # cd $HOME
    os.chdir(env.home)
    # echo "test" > foo
    fd = open(env.testname(t), "w")
    data = "test\n"
    fd.write(data)
    fd.close()
    # Set sequence to return error
    env.set_error("sequence", "NFS4ERR_BADSESSION")
    # cat foo - this compound gets the NFS4ERR_BADSESSION
    fd = open(env.testname(t), "r")
    read = fd.read()
    fd.close()
    # cd $ROOT - test session recovery for root export
    os.chdir(env.root)
    if  read != data:
        fail("'cat foo' = %r, expected %r" % (read, data))

def testSessionReset2(t, env):
    """Test response to server returning NFS4ERR_BADSESSION error on solo SEQUENCE for lease renewal

    FLAGS: sequence all
    CODE: SESSIONRESET2
    """
    """
    cd $HOME
    echo "NFS4ERR_BADSESSION" > $CONFIG/ops/sequence and
    wait the server leasetime so that client renews lease
    cd $ROOT
    """
    # cd $HOME
    os.chdir(env.home)
    # Set sequence to return error and wait lease time
    env.set_error_wait_lease("sequence", "NFS4ERR_BADSESSION")
    # cd $ROOT check session is reset...
    os.chdir(env.root)
