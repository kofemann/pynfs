from __future__ import with_statement
from pnfs_block_pack import PNFS_BLOCKPacker as BlockPacker
from pnfs_block_pack import PNFS_BLOCKUnpacker as BlockUnpacker
from pnfs_block_type import *
from pnfs_block_const import *

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

class FileVolume(object):
    def __init__(self, volume):
        self._vol = volume
        self._pos = 0
        self._end = volume._size
        self._open = []
        self.address_body = volume.get_addr()

    def tell(self):
        return self._pos

    def __enter__(self, mode="rb+"):
        # STUB - need care with mode, for example--append would not work as is
        list = [vol for vol in self._vol._dump() if type(vol) == Simple]
        for vol in list:
            # STUB - rewrite in terms of context managers
            if vol.backing_dev is None:
                raise IOError("No backing device for Simple Volume %i" % vol.id)
            vol._fd = open(vol.backing_dev, mode)
            self._open.append(vol._fd)
        return self

    def __exit__(self, t, v, tb):
        # XXX Careful here - what if errors on a close?
        for fd in reversed(self._open):
            fd.close()
        
    def open(self, mode="rb+"):
        # STUB - need care with mode, for example--append would not work as is
        list = [vol for vol in self._vol._dump() if type(vol) == Simple]
        for vol in list:
            # STUB - rewrite in terms of context managers
            vol._fd = open(vol.backing_dev, mode)
        return self

    def close(self):
        list = [vol for vol in self._vol._dump() if type(vol) == Simple]
        for vol in list:
            # STUB - rewrite in terms of context managers
            vol._fd.close()

    def seek(self, offset, whence=0):
        """Set _pos."""
        # Find new pos
        if whence == 0: # From file start
            newpos = offset
        elif whence == 1: # Relative to pos
            newpos = self._pos + offset
        elif whence == 2: # Relative to end
            newpos = self._end + offset
        # Check bounds
        if 0 <= newpos < self._end:
            self._pos = newpos
        else:
            raise IOError("Pos out of bounds")

    def write(self, str):
        while str:
            vol, pos, limit = self._vol.extent(self._pos, self._end - self._pos)
            vol._fd.seek(pos)
            segment = str[:limit]
            vol._fd.write(segment)
            self._pos += len(segment)
            str = str[limit:]

    def read(self, count=None):
        out = []
        bytes_to_read = self._end - self._pos
        if count is not None and count >= 0:
            bytes_to_read = min(bytes_to_read, count)
        while bytes_to_read:
            vol, pos, limit = self._vol.extent(self._pos, bytes_to_read)
            vol._fd.seek(pos)
            segment = vol._fd.read(limit)
            out.append(segment)
            self._pos += len(segment)
            bytes_to_read -= len(segment)
        return "".join(out)
            
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
        p = BlockPacker()
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
        self._size = size # in blocks
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
#         self._used = 0 # bitmask of blocks assigned to Slices
#         self._lock = Lock()

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
    
#     def get_slice(self, start, length):
#         def set_bits(n):
#             """Set n lower-order bits"""
#             # XXX There is certainly a better way to do this
#             out = 0
#             while n:
#                 out <<= 1
#                 out |= 1
#                 n -= 1
#             return out
#         mask = set_bits(length)
#         mask <<= start
#         self._lock.acquire()
#         try:
#             if mask & self._used:
#                 raise RuntimeError("Already allocated")
#             self._used |= mask
#         finally:
#             self._lock.release()
#         return Slice(self, start, length)

#     def put_slice(self, slice):
#         # STUB - should deallocate slice
#         pass
    
    def _dump(self):
        """Since this is always a leaf node of tree, end recursive scan."""
        return (self, )

    def get_xdr(self, mapping):
        info = pnfs_block_simple_volume_info4(self.sig)
        return pnfs_block_volume4(PNFS_BLOCK_VOLUME_SIMPLE, bv_simple_info=info)

    def resolve(self, i):
        # print "resolve(%i) %r" % (i, self)
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
        # print "resolve(%i) %r" % (i, self)
        # print self.start, self._size, self.length
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
        # print "resolve(%i) %r" % (i, self)
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

# def build_simple(backing_dev):
#     sig = "Fred's python test volume 1"
#     fd = open(backing_dev, "rb+")
#     # Determine device size
#     fd.seek(0, 2)
#     bytes = fd.tell()
#     # Write disk signature
#     fd.seek(-512, 2)
#     fd.write(sig)
#     fd.close()
#     # build topology
#     v1 = Simple(bytes/512, sig)
#     final = Concat([v1])
#     return final

# def build():
#     v1 = Simple(1024, "pyvol1")
#     v2 = Simple(2048, "pyvol2")
#     v3 = Simple(4096, "pyvol3")
#     s1_1 = v1.get_slice(0, 1024) #
#     s2_1 = v2.get_slice(0, 512)   #
#     s2_2 = v2.get_slice(512, 512) # c1
#     s2_3 = v2.get_slice(1024, 512) #
#     s2_4 = v2.get_slice(1536, 512) # c1
#     s3_1 = v3.get_slice(0, 1024)    #
#     s3_2 = v3.get_slice(1024, 1024)
#     s3_3 = v3.get_slice(2048, 1024) #
#     s3_4 = v3.get_slice(3072, 1024)
    
#     s4_1 = Concat([s2_2, s2_4]) #
#     s4_2 = Stripe(64, [s2_1, s2_3])

#     stripe1 = Stripe(256, [s1_1, s3_1, s4_1, s3_3])
#     final = Concat([stripe1, s3_2, s4_2, s3_4])
#     return final

if __name__=="__main__":
    pass
