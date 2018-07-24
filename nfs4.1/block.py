from __future__ import with_statement
from xdrdef.pnfs_block_pack import PNFS_BLOCKPacker as Packer
from xdrdef.pnfs_block_pack import PNFS_BLOCKUnpacker as Unpacker
from xdrdef.pnfs_block_type import *
from xdrdef.pnfs_block_const import *

import fs_base
from threading import Lock
import struct

# draft 8

# All sizes are in bytes unless otherwise indicated

"""
Need to be able to set topology in server_exports
From topology, need to create device
"""

id = 0
id_lock = Lock()

def getid(d):
    """Get a new unique id.  These are used only internally for printing"""
    global id
    id_lock.acquire()
    out = id
    id += 1
    id_lock.release()
    return out

class BlockVolume(fs_base.LayoutFile):
    """Deals with disk topology information"""
    class FakeFs(object):
        def _find_extent(self, pos, inode):
            # inode here is the topology root block.Volume
            vol, v_pos, limit = inode.extent(pos, 1 << 64)
            return fs_base.Extent(fs_base.VALID, v_pos, pos, limit, vol._fd)

    def __init__(self, volume):
        self._component_list = [vol for vol in volume._dump()
                                if type(vol) == Simple]
        self._openlist = []
        self.address_body = volume.get_addr()
        super(BlockVolume, self).__init__(volume, self.FakeFs(), volume._size)

    def open(self, mode="rb+"):
        # STUB - need care with mode, for example--append would not work as is
        for vol in self._component_list:
            # STUB - rewrite in terms of context managers
            if vol.backing_dev is None:
                raise IOError("No backing device for Simple Volume %i" % vol.id)
            vol._fd = open(vol.backing_dev, mode)
            self._openlist.append(vol._fd)
        return self

    def close(self):
        # XXX Careful here - what if errors on a close, or previously on open?
        for fd in reversed(self._openlist):
            fd.close()

    __enter__ = open

    def __exit__(self, t, v, tb):
        self.close()

class Volume(object):
    """Superclass used to represent topology components."""

    def get_addr(self):
        """Generate the opaque part of device_addr4 used by NFS4.1.

        Note this corresponds to device.address_body property used by
        op_getdeviceinfo.
        """
        # Create list of all volumes referenced, in order of reference
        list = self._dump()
        # Create mapping from device to its index in list
        mapping = dict(zip(list, range(len(list))))
        # Create (unpacked) pnfs_block_volume4 structure for each volume
        addr = pnfs_block_deviceaddr4([d.get_xdr(mapping) for d in list])
        # Create packed xdr string
        p = Packer()
        p.pack_pnfs_block_deviceaddr4(addr)
        return p.get_buffer()

    def _dump(self):
        """Recursively scan for all devices in tree.

        They are returned in order of reference, to build volume array.
        """
        out = []
        for v in self.volumes:
            out.extend(v._dump())
        out = remove_dups(out)
        out.append(self)
        return out

    def get_xdr(self, mapping):
        """Returns filled (and unpacked) pnfs_block_volume4 structure.

        Need mapping from device:to top-level array index to do the conversion.
        """
        raise NotImplementedError

    def resolve(self, i):
        """Map a byte offset to the corresponding Simple volume and byte offset.
        """
        return NotImplementedError

    def extent(self, i, limit):
        """Same as resolve, with addition of how far mapping extends."""
        return NotImplementedError

class Simple(Volume):
    """Represents an actual disk.  Always a leaf node in the topology tree."""
    def __init__(self, signature, size=None, backing_dev=None):
        self.type = PNFS_BLOCK_VOLUME_SIMPLE
        self.id = getid(self)
        if type(signature[0]) == int:
            # Make it easy to send a single component
            signature = [signature]
        self.sig = [pnfs_block_sig_component4(i, s) for i, s in signature]
        self._size = size # in bytes
        self.backing_dev = backing_dev
        if backing_dev is None:
            if size is None:
                raise ValueError("Must set either size or backing_dev")
            return
        self._fd = None
        with open(backing_dev, "rb+") as fd:
            # Determine device's actual size
            fd.seek(0, 2)
            true_size = fd.tell()
            if size is None:
                self._size = true_size
            elif true_size < size:
                raise ValueError("backing dev size %r < %r" % (true_size, size))
            self._write_sig(fd)

    def _write_sig(self, fd):
        """Write out disk signature to open fd."""
        for comp in self.sig:
            offset = comp.bsc_sig_offset
            if offset < 0:
                offset += self._size
            fd.seek(offset)
            fd.write(comp.bsc_contents)

    def __repr__(self):
        return "Simple %i" % self.id

    def _dump(self):
        """Since this is always a leaf node of tree, end recursive scan."""
        return (self, )

    def get_xdr(self, mapping):
        info = pnfs_block_simple_volume_info4(self.sig)
        return pnfs_block_volume4(PNFS_BLOCK_VOLUME_SIMPLE, bv_simple_info=info)

    def resolve(self, i):
        # print("resolve(%i) %r" % (i, self))
        if i < 0 or i >= self._size:
            raise ValueError("Asked for %i of %i" % (i, self._size))
        return (self, i)

    def extent(self, i, limit):
        return (self, i, min(limit, self._size - i))

class Slice(Volume):
    """A contiguous slice from a single volume."""
    def __init__(self, volume, start, length):
        self.type = PNFS_BLOCK_VOLUME_SLICE
        self.id = getid(self)
        self.start = start # block offset
        self.length = length # length in blocks
        self.volumes = [volume] # volume which is sliced
        self._size = length

    def __repr__(self):
        return "Slice %i (from vol %i)" % (self.id, self.volumes[0].id)

    def get_xdr(self, mapping):
        info = pnfs_block_slice_volume_info4(self.start, self.length,
                                             mapping[self.volumes[0]])
        return pnfs_block_volume4(PNFS_BLOCK_VOLUME_SLICE, bv_slice_info=info)

    def resolve(self, i):
        # print("resolve(%i) %r" % (i, self))
        # print(self.start, self._size, self.length)
        if i < 0 or i >= self._size:
            raise ValueError("Asked for %i of %i" % (i, self._size))
        return self.volumes[0].resolve(self.start + i)

    def extent(self, i, limit):
        return self.volumes[0].extent(self.start + i,
                                      min(limit, self._size - i))

class Concat(Volume):
    """A simple concatanation of several volumes."""
    def __init__(self, volumes):
        self.type = PNFS_BLOCK_VOLUME_CONCAT
        self.id = getid(self)
        self.volumes = volumes
        self._size = sum([v._size for v in volumes])

    def get_xdr(self, mapping):
        info = pnfs_block_concat_volume_info4([mapping[v] for v in self.volumes])
        return pnfs_block_volume4(PNFS_BLOCK_VOLUME_CONCAT, bv_concat_info=info)

    def __repr__(self):
        return "Concat %i of %r" % (self.id, [v.id for v in self.volumes])

    def resolve(self, i):
        # print("resolve(%i) %r" % (i, self))
        if i < 0 or i >= self._size:
            raise ValueError("Asked for %i of %i" % (i, self._size))
        sum = 0
        for v in self.volumes:
            next = sum + v._size
            if i < next:
                return v.resolve(i - sum)
            sum = next
        # Shouldn't get here
        raise RuntimeError

    def extent(self, i, limit):
        sum = 0
        for v in self.volumes:
            next = sum + v._size
            if i < next:
                return v.extent(i - sum, min(limit, next - i))
            sum = next
        # Shouldn't get here
        raise RuntimeError

class Stripe(Volume):
    """Stripe of several volumes, all of the same size."""
    def __init__(self, size, volumes):
        self.type = PNFS_BLOCK_VOLUME_STRIPE
        self.id = getid(self)
        self.stripe_unit = size # in blocks?
        self.volumes = volumes
        self._size = sum([v._size for v in volumes]) # XXX All same size?

    def get_xdr(self, mapping):
        info = pnfs_block_stripe_volume_info4(self.stripe_unit,
                                              [mapping[v] for v in self.volumes])
        return pnfs_block_volume4(PNFS_BLOCK_VOLUME_STRIPE, bv_stripe_info=info)

    def __repr__(self):
        return "Slice %i (size=%i) of %r" % (self.id, self.stripe_unit,
                                             [v.id for v in self.volumes])

    def resolve(self, i):
        """
         0 1 2 3 4 5 6 7 8  global_stripe_number
        |     |     |     |
        | | | | | | | | | |
        |     |     |     |
           0     1     2    local_stripe_number
         0 1 2 0 1 2 0 1 2  disk_number
        """
        def split(x, mod):
            return (x // mod, x % mod)

        if i < 0 or i >= self._size:
            raise ValueError("Asked for %i of %i" % (i, self._size))
        global_stripe_number, stripe_pos = split(i, self.stripe_unit)
        local_stripe_number, disk_number = split(global_stripe_number,
                                                 len(self.volumes))
        disk_pos = local_stripe_number * self.stripe_unit + stripe_pos
        return self.volumes[disk_number].resolve(disk_pos)

    def extent(self, i, limit):
        def split(x, mod):
            return (x // mod, x % mod)

        global_stripe_number, stripe_pos = split(i, self.stripe_unit)
        local_stripe_number, disk_number = split(global_stripe_number,
                                                 len(self.volumes))
        disk_pos = local_stripe_number * self.stripe_unit + stripe_pos
        return self.volumes[disk_number].extent(disk_pos, min(limit, self.stripe_unit - stripe_pos))

def remove_dups(l):
    # XXX Again, is a better way
    out = []
    while l:
        i = l.pop(0)
        if i not in out:
            out.append(i)
    return out

if __name__=="__main__":
    pass
