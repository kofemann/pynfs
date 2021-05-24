from __future__ import with_statement
import threading


DEBUG = False # Note this only affects locks at creation

class Counter(object):
    def __init__(self, first_value=0, name="counter"):
        self._lock = Lock(name)
        self._value = first_value

    def next(self):
        with self._lock:
            out = self._value
            self._value += 1
        return out

def Lock(name=""):
    if DEBUG:
        return _DebugLock(name)
    else:
        return threading.Lock()

def RWLock(name=""):
    if DEBUG:
        return _RWLockVerbose(name)
    else:
        return _RWLock()

def _collect_acq_data(suffix=""):
    """Debugging decorator for lock acquire"""
    def _deco(acquire):
        def wrapper(self):
            suf = ("" if not suffix else "_%s" % suffix)
            print("ACQUIRE%s tried for lock %s" % (suf.upper(), self.name))
            t = threading.currentThread()
            try:
                t.locks[self.name] = "waiting%s" % suf
            except AttributeError:
                t.locks = {self.name: "waiting%s" % suf}
            acquire(self)
            t.locks[self.name] = "holding%s" % suf
            print("ACQUIRE%s succeeded for lock %s" % (suf.upper(), self.name))
        return wrapper
    return _deco

def _collect_rel_data(suffix=""):
    """Debugging decorator for lock release"""
    def _deco(release):
        def wrapper(self, *args, **kwargs):
            suf = ("" if not suffix else "_%s" % suffix)
            print("RELEASE%s lock %s" % (suf.upper(), self.name))
            t = threading.currentThread()
            t.locks[self.name] = "released%s" % suf
            release(self, *args, **kwargs)
        return wrapper
    return _deco

class _DebugLock(object):
    def __init__(self, name):
        # Note threading.Lock is a generator function, so can't subclass
        self.lock = threading.Lock()
        self.name = name


    @_collect_acq_data()
    def acquire(self):
        self.lock.acquire()

    __enter__ = acquire

    @_collect_rel_data()
    def release(self):
        self.lock.release()

    def __exit__(self, t, v, tb):
        self.release()

class _RWLock(object):
    """
    want: acquire() - gets read lock, which merely causes writelock to block
    want: release()
    want: acquire_write() - Once have this lock, no one else can
          do anything. Blocks until all read locks are gone.  Also
          cause any requests for read locks to block.
    """
    # NOTE - in case of read-only filesystem, want acquire/release to
    # revert to NOPs, while acquire-write should raise error.

    def __init__(self):
        self._cond = threading.Condition()
        self._write_lock = threading.Lock()
        self._write_count = 0 # Number who *want* or *have* write lock
        self._read_count = 0 # Number who *want* or *have* read lock
        self._read_lock = 0 # Number who *have* read lock

    def acquire(self):
        with self._cond:
            self._acquire_read()

    def acquire_write(self):
        """Acquire write lock.

        Note this will deadlock if thread also has a read lock.
        """
        with self._cond:
            self._acquire_write()

    def release(self):
        """Releases lock, first determining the correct type"""
        with self._cond:
            if self._read_lock:
                self._release_read()
            else:
                self._release_write()

    def upgrade(self):
        """Upgrade to write lock, assuming thread has read lock already"""
        with self._cond:
            self._release_read(notify=False)
            self._acquire_write()

    def downgrade(self):
        """Downgrade to read lock, assuming thread has write lock already"""
        with self._cond:
            self._release_write()
            self._acquire_read()

    def _acquire_read(self):
        self._read_count += 1
        while self._write_count > 0:
            self._cond.wait()
        else:
            self._read_lock += 1

    def _release_read(self, notify=True):
        self._read_count -= 1
        self._read_lock -= 1
        if notify and self._read_lock == 0:
            # We really want to only wake one write thread, but there
            # might be read threads waiting too.
            self._cond.notifyAll()
        elif self._read_lock < 0:
            raise ValueError("Unmatched release")

    def _acquire_write(self):
        """Acquire write lock.

        Note this will deadlock if thread also has a read lock.
        """
        self._write_count += 1
        while self._read_lock > 0:
            self._cond.wait()
        else:
            while not self._write_lock.acquire(False):
                self._cond.wait()

    def _release_write(self):
        self._write_count -= 1
        self._write_lock.release()
        # Must always notify, since might be write-lockers waiting
        self._cond.notifyAll()

class _RWLockVerbose(_RWLock):
    """
    want: acquire() - gets read lock, which merely causes writelock to block
    want: release()
    want: acquire_write() - Once have this lock, no one else can
          do anything. Blocks unitil all read locks are gone.  Also
          cause any requests for read locks to block.
    """
    # NOTE - in case of read-only filesystem, want acquire/release to
    # revert to NOPs, while acquire-write should raise error.

    def __init__(self, name=""):
        super(_RWLockVerbose, self).__init__()
        self.name = "RWLock_%s" % name

    @_collect_acq_data("read")
    def _acquire_read(self):
        super(_RWLockVerbose, self)._acquire_read()

    @_collect_rel_data("read")
    def _release_read(self, *args, **kwargs):
        super(_RWLockVerbose, self)._release_read(*args, **kwargs)

    @_collect_acq_data("write")
    def _acquire_write(self):
        super(_RWLockVerbose, self)._acquire_write()

    @_collect_rel_data("write")
    def _release_write(self):
        super(_RWLockVerbose, self)._release_write()
