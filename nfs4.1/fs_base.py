# These are the extent types
# HOLE - no disk mapping, read returns 0's
# VALID - mapped to disk and initialized
# INVALID - mapped to disk, but not zeroed
# EOF - no disk mapping, any use should be an error

HOLE, VALID, INVALID, EOF = range(4)

class Extent(object):
    def __init__(self, type, v_pos, f_pos, length, volume):
        self.type = type
        self.v_pos = v_pos
        self.f_pos = f_pos
        self.length = length
        self.volume = volume

class LayoutFile(object):
    """A file-like object"""
    def __init__(self, inode, fs, size=None):
        # inode is identifier that fs assigns this object
        if size is None:
            self._size = 0 # Location of EOF
            self.resizable = True
        else:
            self._size = size
            self.resizable = False
        self._pos = 0
        self._fs = fs
        self._inode = inode

    def seek(self, offset, whence=0):
        # Find new pos
        if whence == 0: # From file start
            newpos = offset
        elif whence == 1: # Relative to pos
            newpos = self._pos + offset
        elif whence == 2: # Relative to end
            newpos = self._size + offset
        # Check bounds
        if self.resizable or (0 <= newpos < self._size):
            self._pos = newpos
        else:
            raise IOError("Pos out of bounds")

    def tell(self):
        return self._pos

    def read(self, count=None):
        out = []
        bytes_to_read = max(0, self._size - self._pos)
        if count is not None and count >= 0:
            bytes_to_read = min(bytes_to_read, count)
        while bytes_to_read:
            e = self._find_extent(self._pos)
            limit = min(e.length, bytes_to_read)
            if e.type == HOLE:
                segment = '\0' * limit
            else:
                e.volume.seek(e.v_pos)
                segment = e.volume.read(limit)
            out.append(segment)
            self._pos += len(segment)
            bytes_to_read -= len(segment)
        return "".join(out)

    def write(self, str):
        # Note here we need not check >=, since = results in a nop
        if str and self._pos > self._size:
            self._create_hole(self._size, self._pos - self._size)
        while str:
            e = self._find_extent(self._pos)
            if e.type == EOF:
                # Cause next _find_extent to return initialized valid extent
                self._map_extent(self._pos, len(str))
            elif e.type == HOLE:
                # Cause next _find_extent to return initialized valid extent
                self._map_extent(self._pos, min(e.length, len(str)))
                continue
            e.volume.seek(e.v_pos)
            segment = str[:e.length]
            e.volume.write(segment)
            self._pos += len(segment)
            str = str[e.length:]
        if self._pos > self._size:
            self._size = self._pos

    def _find_extent(self, pos):
        e = self._fs._find_extent(pos, self._inode)
        if e.type == INVALID:
            raise IOError("Tried to use uninitialized extent")
        return e
