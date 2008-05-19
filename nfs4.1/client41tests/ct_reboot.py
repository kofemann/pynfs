import os

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
        
