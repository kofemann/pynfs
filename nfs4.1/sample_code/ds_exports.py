"""
A very simple exports file intended for use with a files-layout dataserver.
"""

from fs import StubFS_Mem

def mount_stuff(server, opts):
    B = StubFS_Mem(2)
    server.mount(B, path="/pynfs_mds")
