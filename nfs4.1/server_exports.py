from fs import StubFS_Mem, StubFS_Disk, BlockLayoutFS


def mount_stuff(server, opts):
    """Mount some filesystems to the server"""
    # STUB - just testing stuff out
    A = StubFS_Disk("/tmp/py41/fs1", opts.reset, 1)
    B = StubFS_Mem(2)
    C = StubFS_Mem(3)
    server.mount(A, path="/a")
    server.mount(B, path="/b")
    server.mount(C, path="/foo/bar/c")
    if opts.use_block:
        dev = _create_simple_block_dev()
        E = BlockLayoutFS(5, backing_device=dev)
        server.mount(E, path="/block")

def _create_simple_block_dev():
    from block import Simple, Slice, Concat, Stripe, FileVolume
    v1 = Simple([(-512, "Fred's python test volume 1, comp 1"),
                 (-1024, "Can we handle a second sig component?")],
                backing_dev = "/dev/ram4")
    length = v1._size / 4
    s1 = Slice(v1, 0, length)
    s2 = Slice(v1, length, length)
    s3 = Slice(v1, 2*length, length)
    c1 = Concat([s3, s1])
    return FileVolume(c1)
