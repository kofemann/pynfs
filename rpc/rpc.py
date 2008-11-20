import socket, select
import struct
import inspect
import time
import threading
import logging
import collections

import rpc_pack
from rpc_const import *
from rpc_type import *

import security
from security import RPCReply

log_p = logging.getLogger("rpc.poll") # polling loop thread
log_t = logging.getLogger("rpc.thread") # handler threads

# log_p.setLevel(logging.DEBUG)
# log_t.setLevel(logging.DEBUG)

LOOPBACK = "127.0.0.1"

def inc_u32(i):
    """Increment a 32 bit integer, with wrap-around."""
    return int( (i+1) & 0xffffffff )

class RPCError(Exception):
    pass

class RPCTimeout(RPCError):
    pass

class RPCAcceptError(RPCError):
    def __init__(self, a):
        self.verf = a.verf
        a = a.reply_data
        self.stat = a.stat
        if self.stat == PROG_MISMATCH:
            self.low = a.mismatch_info.low
            self.high = a.mismatch_info.high

    def __str__(self):
        if self.stat == PROG_MISMATCH:
            return "RPCError: MSG_ACCEPTED: PROG_MISMATCH [%i,%i]" % \
                   (self.low, self.high)
        else:
            return "RPCError: MSG_ACCEPTED: %s" % \
                   accept_stat.get(self.stat, self.stat)

class RPCDeniedError(RPCError):
    def __init__(self, r):
        self.stat = r.stat
        if self.stat == RPC_MISMATCH:
            self.low = r.mismatch_info.low
            self.high = r.mismatch_info.high
        elif self.stat == AUTH_ERROR:
            self.astat = r.astat

    def __str__(self):
        if self.stat == RPC_MISMATCH:
            return "RPCError: MSG_DENIED: RPC_MISMATCH [%i,%i]" % \
                   (self.low, self.high)
        else:
            return "RPCError: MSG_DENIED: AUTH_ERROR: %s" % \
                   auth_stat.get(self.astat, self.astat)

class CredProblem(rpc_pack.XDRError):
    def __init__(self, data):
        self.data = data

###################################################

class FancyRPCUnpacker(rpc_pack.RPCUnpacker):
    """RPC headers contain opaque credentials.  Try to de-opaque them."""
    def _filter_opaque_auth(self, py_data):
        # NOTE Can't use this in general, because GSS uses different
        # encodings depending on circumstance.  Instead we call this
        # from other filter as needed.
        try:
            klass = security.klass(py_data.flavor)
        except:
            # An unsupported security flavor.
            # This will be dealt with by message handler.
            return py_data
        try:
            body = klass.unpack_cred(py_data.body)
            out = opaque_auth(py_data.flavor, body)
            # HACK - lets other code know this has been expanded
            out.opaque = False
            return out
        except:
            # We had a bad XDR within GSS cred.  This shouldn't propagate up
            # as bad XDR of RPC.  Instead, we just leave it as is.
            return py_data

    def filter_call_body(self, py_data):
        # Can't overwrite py_data, so don't just do py_data.cred = ...
        return call_body(py_data.rpcvers, py_data.prog, py_data.vers,
                         py_data.proc,
                         self._filter_opaque_auth(py_data.cred),
                         py_data.verf)

class FancyRPCPacker(rpc_pack.RPCPacker):
    """RPC headers contain opaque credentials which may have been expanded.

    Make sure they are put back to opaques.
    """
    def _filter_opaque_auth(self, py_data):
        # NOTE Can't use this in general, because GSS uses different
        # encodings depending on circumstance.  Instead we call this
        # from other filter as needed.
        if getattr(py_data, "opaque", True):
            return py_data
        # We don't use "try" block, since any exception is a bug
        # that should be raised.
        klass = security.klass(py_data.flavor)
        return opaque_auth(py_data.flavor, klass.pack_cred(py_data.body))

    def filter_call_body(self, py_data):
        # Can't overwrite py_data, so don't just do py_data.cred = ...
        return call_body(py_data.rpcvers, py_data.prog, py_data.vers,
                         py_data.proc,
                         self._filter_opaque_auth(py_data.cred),
                         py_data.verf)
        
###################################################

class DeferredData(object):
    def __init__(self, msg=None, lock=None):
        self.lock = threading.Condition(lock) # XXX Is this better as Event()?
        self.data = None
        self.exception = None
        self.filled = False
        self.msg = msg # Data that thread calling fill might need
        
    def wait(self, timeout=None):
        """Wait for data to be filled in"""
        self.lock.acquire()
        if not self.filled:
            # NOTE because lock is held, there is no race here w/ self.filled
            self.lock.wait(timeout)
        filled = self.filled # Make local copy before giving up lock
        self.lock.release()
        if not filled:
            raise RPCTimeout
        if self.exception is not None:
            raise self.exception

    def fill(self, data=None, exception=None):
        """Fill with data, and flag that this has been done.

        Caller should no longer reference the object afterwards.
        """
        self.exception = exception
        self.data = data
        self.lock.acquire()
        self.filled = True
        self.lock.notifyAll()
        self.lock.release()

class _MyDeque(collections.deque):
    # XXX Should we reimplement close?
    # Sole purpose of this is to allow attrs to be writable,
    # which is used to implement close.
    pass

class Alarm(object):
    """A method of notifying select loop that there is data waiting"""
    def __init__(self, address):
        # XXX I don't think the locking is needed now that select counts bytes
        # self.lock = threading.Lock()
        self.queue = collections.deque()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setblocking(0)
        try:
            self.s.connect(address)
        except socket.error:
            # Should get op in progress error
            pass
        
    def buzz(self, info):
        """Wake the polling loop, passing it info"""
        # self.lock.acquire()
        try:
            self.queue.appendleft(info)
            # Send one byte of data to wake select loop
            # Note bytes sent are counted to determine how many items to pop
            while (not self.s.send('\0')):
                # Just loop here until we actually send something
                pass
        finally:
            # self.lock.release()
            pass

    def __getattr__(self, attr):
        """Show socket interface"""
        return getattr(self.s, attr)

class Pipe(object):
    """Groups a socket with its buffers."""
    def __init__(self, socket):
        self.s = socket
        self.timestamp = int(100*time.time())
        # Note the write queue is accessed by both main and worker threads,
        # so uses thread-safe deque() struture.  The other buffers are only
        # looked at by the main thread, so no locking is required.
        self.write_queue = _MyDeque() # Records waiting to be sent out
        # records are pulled from write_queue, record marking added, then
        # the raw data to be written out is put here
        self.write_buf = '' # Raw outgoing data
        self.read_buf = '' # Raw incoming data
        self.packet_buf = [] # Store packets read until have a whole record
        self.lock = threading.Lock()
        self.xid = 0
        self.pending = {} # {xid:defer}
        self._close_lock = threading.Lock()

    def __getattr__(self, attr):
        """Show socket interface"""
        return getattr(self.s, attr)

    def connection(self):
        """Returns info uniquely identifying the connection"""
        return self.s.fileno(), self.timestamp

    def get_xid(self):
        self.lock.acquire()
        out = self.xid
        self.xid = inc_u32(out)
        self.lock.release()
        return out

    def listen(self, xid, timeout=None):
        self.pending[xid].wait(timeout)
        reply = self.pending[xid].data
        del self.pending[xid]
        return reply

    def __str__(self):
        return "pipe-%i" % self.s.fileno()

#################################################

class ConnectionHandler(object):
    """Common code for server and client.

    Sets up polling and event dispatching, and deals with RPC headers, xids,
    and record marking in the communication streams.

    NOTE that the _event_* functions should not be called directly,
    but only through start.  Thread safety depends on this.
    """
    def __init__(self):
        # Set up polling lists
        self.readlist = set()
        self.writelist = set()
        self.errlist = set()
        # A list of all sockets we have open, indexed by fileno
        self.sockets = {} # {fd: pipe}
        # A list of the sockets set to listen for connections
        self.listeners = set()

        # Create internal server for alarm system to connect to
        self.s = self.expose((LOOPBACK, 0), False)
        
        # Set up alarm system, which is how other threads inform the polling
        # thread that data is ready to be sent out
        # NOTE that there are TWO sockets associated with alarm, one
        # for each end of the connection.  Nasty bugs creep in here.
        self.write_alarm = Alarm(self.s.getsockname())
        self.write_alarm_poll = self._event_connect_incoming(self.s.fileno())

        # We have another alarm to deal with sockets created by other threads
        self.socket_alarm = Alarm(self.s.getsockname())
        self.socket_alarm_poll = self._event_connect_incoming(self.s.fileno())

        # Set up some constants that effect general behavior
        self.rsize = 4096 # Read data in chunks of this size
        self.wsize = 4098 # Read data in chunks of this size
        self.rpcversions = (2,) # Supported RPC versions

    def start(self):
        while 1:
            log_p.debug("Calling select")
            log_p.log(5, "Sleeping for: %s, %s, %s" %
                 (self.readlist, self.writelist, self.errlist))
            r,w,e = select.select(self.readlist, self.writelist, self.errlist)
            log_p.log(5, "Woke with: %s, %s, %s" % (r, w, e))
            for fd in e:
                log_p.warn(1, "polling error from %i" % fd)
                # STUB - now what?
            for fd in w:
                self._event_write(fd)
            for fd in r:
                if fd in self.listeners: #== self.s.fileno():
                    self._event_connect_incoming(fd)
                elif fd == self.write_alarm_poll.fileno():
                    # We have a reply ready to be sent out
                    log_p.log(5, "Woke due to write alarm")
                    # data from alarm has one byte garbage per socket
                    data = self.write_alarm_poll.recv(self.rsize)
                    # Real info is the list of sockets ready to write data
                    list = [self.write_alarm.queue.pop() for i in data]
                    self.writelist |= set(list)
                elif fd == self.socket_alarm_poll.fileno():
                    # We have initiated a client-like connection
                    log_p.log(5, "Woke due to connection alarm")
                    # data from alarm has one byte garbage per socket
                    data = self.socket_alarm_poll.recv(self.rsize)
                    # Real info is list of pipes to add to self.sockets
                    list = [self.socket_alarm.queue.pop() for i in data]
                    self._event_new_socket(list)
                else:
                    try:
                        data = self.sockets[fd].recv(self.rsize)
                    except socket.error:
                        data = None
                    if data:
                        self._event_read(data, fd)
                    else:
                        self._event_close(fd)

    def _event_connect_incoming(self, fd):
        """Someone else is trying to connect to us (we act like server)."""
        s = self.sockets[fd]
        csock, caddr = s.accept()
        csock.setblocking(0)
        fd = csock.fileno()
        pipe = self.sockets[fd] = Pipe(csock)
        log_p.info("got connection from %s, assigned to fd=%i" %
             (csock.getpeername(), fd))
        # Start listening for data to come in on new connection
        self.readlist.add(fd)
        self.errlist.add(fd)
        return pipe

    def _event_new_socket(self, list):
        """We have a new socket that polling loop needs to know about"""
        for pipe, defer in list:
            fd = pipe.fileno()
            log_p.info("Adding %i generated by another thread" % fd)
            # Add to known connections
            self.sockets[fd] = pipe
            # Start listening on new connection
            self.readlist.add(fd)
            self.errlist.add(fd)
            # Notify thread which created connection that it is now up
            defer.fill()
            
    def _event_close(self, fd):
        """Close the connection, and remove references to it."""
        log_p.info("Closing %i" % fd)
        temp = set([fd])
        self.writelist -= temp
        self.readlist -= temp
        self.errlist -= temp
        self.sockets[fd].close()
        del self.sockets[fd]

    def _event_write(self, fd):
        """Data is waiting to be written."""
        s = self.sockets[fd]
        if not s.write_buf:
            # Pop record off the write queue, and format it for the wire
            try:
                data = s.write_queue.pop()
                if data is None:
                    log_p.info("Write queue is flushed for %i" % fd)
                    # The pipe has been closed
                    self._event_close(fd)
                    return
                s.write_buf = self.add_record_marks(data)
            except IndexError:
                # NOTE that due to threading, it is possible that write_queue
                # is no longer empty when we get here.  However, that's OK,
                # since that means an alarm is pending, which will then
                # add fd back to writelist.
                self.writelist.remove(fd)
                log_p.log(5, "Finished writing to %i" % fd)
                return
        log_p.log(4, "Writing to %i" % fd)
        count = s.send(s.write_buf)
        s.write_buf = s.write_buf[count:]
        
    def add_record_marks(self, data):
        """Given a record, convert it to actual stream to send over TCP"""
        dlen = len(data)
        i = last = 0
        out = '' # FRED - use stringio here?
        while not last:
            chunk = data[i:i+self.wsize]
            i += self.wsize
            if i >= dlen:
                last = 0x80000000L
            mark = struct.pack('>L', last | len(chunk))
            out += mark + chunk
        return out
        
    def _event_read(self, data, fd):
        """Data is waiting to be read.

        Wait until we get a full RPC record, then dispatch it to a thread.
        """
        log_p.log(5, "Received data from %i" % fd)
        log_p.log(2, repr(data))
        s = self.sockets[fd]
        s.read_buf += data
        while s.read_buf:
            buf = s.read_buf
            if len(buf) < 4:
                # We don't even have the packet length yet, wait for more data
                return
            packetlen = struct.unpack('>L', buf[0:4])[0]
            last = 0x80000000L & packetlen
            packetlen &= 0x7fffffffL
            packetlen += 4 # Include size of record mark
            if len(buf) < packetlen:
                # We don't have a full packet yet, wait for more data
                return
            s.packet_buf.append(buf[4:packetlen])
            s.read_buf = buf[packetlen:]
            if last:
                # We finally have a full RPC record, have a thread deal with it
                # Note this means we have the last packet of a record, it
                # does not mean that s.read_buf is empty
                log_p.debug("Received full record from %i" % fd)
                record = ''.join(s.packet_buf)
                s.packet_buf = []
                log_p.log(3, repr(record))
                t = threading.Thread(target=self._event_rpc_record,
                                     args=(record, s))
                t.setDaemon(True)
                t.start()

    def _event_rpc_record(self, record, pipe):
        """Deal with an incoming RPC record.

        This is run in its own thread.
        """
        log_t.log(5, "_event_rpc_record thread receives %r" % record)
        # log_t.info("_event_rpc_record thread receives %r" % record)
        try:
            p = FancyRPCUnpacker(record)
            msg = p.unpack_rpc_msg() # RPC header
            msg_data = record[p.get_position():] # RPC payload
            # Remember which connection msg was received on
            msg.pipe = pipe
            # Remember length of the header
            msg.length = p.get_position()
        except (rpc_pack.XDRError, EOFError), e:
            log_t.warn("XDRError: %s, dropping packet" % e)
            log_t.debug("unpacking raised the following error", exc_info=True)
            return # Drop incorrectly encoded packets
        log_t.debug("MSG = %s" % str(msg))
        log_t.debug("data = %r" % msg_data)
        if msg.mtype == REPLY:
            self._event_rpc_reply(msg, msg_data)
        elif msg.mtype == CALL:
            self._event_rpc_call(msg, msg_data)
        else:
            # Shouldn't get here, but doesn't hurt
            log_t.error("Received rpc_record with msg.type=%i" % msg.type)
        return

    def _event_rpc_reply(self, msg, msg_data):
        """Deal with an incoming RPC REPLY.

        msg is unpacked header, with pipe field added.
        msg_data is raw procedure data.
        """
        try:
            # This should match a CALL we made, which set aside space for us
            # (The space is set aside in self.send_raw)
            deferred = msg.pipe.pending[msg.xid]
        except IndexError:
            log_t.warn("Reply with unexpected xid=%i" % msg.xid)
            return
        header = msg.body
        try:
            if header.mtype != REPLY:
                raise RPCError("Msg was not a REPLY")
            if header.stat == MSG_DENIED:
                raise RPCDeniedError(header.rreply)
            sec = deferred.msg.sec
            # BUG - how handle exception from check_reply_verf?
            sec.check_reply_verf(msg, deferred.msg.body.cred, msg_data)
            if header.reply_data.stat != SUCCESS:
                raise RPCAcceptError(header.areply)
            msg_data = sec.unsecure_data(deferred.msg.body.cred, msg_data)
        except RPCError, e:
            log_t.warn("Filling deferral %i with an exception" % msg.xid)
            deferred.fill((msg, msg_data), e)
            return
        log_t.debug("Filling deferral %i" % msg.xid)
        deferred.fill((msg, msg_data))

    def _event_rpc_call(self, msg, msg_data):
        """Deal with an incoming RPC CALL.
        
        msg is unpacked header, with pipe and length fields added.
        msg_data is raw procedure data.
        """
        """Given an RPC record, returns appropriate reply

        This is run in its own thread.
        """
        class XXX(object):
            pass
        call_info = XXX() # Store various info we need to pass to procedure
        call_info.header_size = msg.length
        call_info.payload_size = len(msg_data)
        call_info.connection = msg.pipe.connection() # XXX Use just msg.pipe?
        sec = None
        notify = None
        try:
            # Check for reasons to DENY the call
            self._check_rpcvers(msg)
            call_info.credinfo = self._check_auth(msg, msg_data)
            sec = call_info.credinfo.sec
            # Call has been ACCEPTED, now check for reasons not to succeed
            msg_data = sec.unsecure_data(msg.body.cred, msg_data)
            self._check_program(msg)
            self._check_version(msg)
            method = self.find_method(msg)
            # Everything looks good at this layer, time to do the call
            tuple = method(msg_data, call_info)
            if len(tuple) == 2:
                status, result = tuple
            else:
                status, result, notify = tuple
            # status, result = method(msg_data, call_info)
            log_t.debug("Called method, got %r, %r" % (status, result))
            raise RPCReply(stat=status, msgdata=result)
        except RPCReply, e:
            if e.drop:
                # Silently drop the request
                log_t.warn("Dropped request")
                return
            else:
                body, data = e.body(sec, msg.body.cred)
                self.send_reply(msg.pipe, msg.xid, body, data)
        if notify is not None:
            notify()

    def find_method(self, msg):
        """Returns RPC function to call

        We look for self.handle_<proc>.  If that does not exist
        we look for self.handle_<proc>_v<vers>.  If that does not exist,
        we send an RPC error and return None.
        """
        method = getattr(self, 'handle_%i' % msg.proc, None)
        if method is not None:
            return method
        method = getattr(self, 'handle_%i_v%i' % (msg.proc, msg.vers), None)
        if method is not None:
            return method
        log_t.warn("PROC_UNAVAIL for vers=%i, proc=%i" % (msg.vers, msg.proc))
        raise RPCReply(stat=PROC_UNAVAIL)

    def _check_version(self, msg):
        """Returns True if program version is supported"""
        if msg.vers not in self.versions:
            log_t.warn("PROG_MISMATCH, do not support vers=%i" % msg.vers)
            raise RPCReply(stat=PROG_MISMATCH,
                           statdata=(min(self.versions), max(self.versions)))

    def _check_program(self, msg):
        """Returns True if call program is supported"""
        if msg.prog != self.prog:
            log_t.warn("PROG_UNAVAIL, do not support prog=%i" % msg.prog)
            raise RPCReply(stat=PROG_UNAVAIL)

    def _check_rpcvers(self, msg):
        """Returns True if rpcvers is ok, otherwise sends out MSG_DENIED"""
        if msg.rpcvers not in self.rpcversions:
            log_t.warn("RPC_MISMATCH, do not support vers=%i" % msg.rpcvers)
            raise RPCReply(accept=False, stat=RPC_MISMATCH,
                           statdata=(min(self.rpcversions),
                                     max(self.rpcversions)))

    def _check_auth(self, msg, data):
        """Returns security module to use if call processing should continue,

        otherwise returns None.
        Note that it is possible for security module to hijack call processing.
        """
        # Check that flavor is supported
        try:
            sec = self.security[msg.cred.flavor]
        except KeyError:
            log_t.warn("AUTH_ERROR: Unsupported flavor %i" % msg.cred.flavor)
            if msg.proc == 0 and msg.cred.flavor == AUTH_NONE:
                # RFC 1831 section 11.1 says "by convention" should allow this
                log_t.warn("Allowing NULL proc through anyway")
                sec = security.klass(AUTH_NONE)()
            else:
                raise RPCReply(accept=False,
                               stat=AUTH_ERROR, statdata=AUTH_FAILED)
        # Call flavor specific authority checks
        return sec.check_auth(msg, data)

        # What incoming flavors do I allow?
        #    How does server learn/change these defaults

        # For AUTH_NONE:
        #   return True - note 11.1 says "by convention" should
        #   allow AUTH_NONE, at least for proc==0

        # For AUTH_SYS:
        #    check machinename, mode - again how is accept list set on server?
        
        # For GSS:
        #   illegal enum values should return AUTH_BADCRED
        #      this will be noticed by XDR unpack failing, which means
        #      type(cred.body) == str
        #   check gss_version, fail with AUTH_BADCRED
        #   check allows service - again how does server set?
        #   check context handle - what does this mean?
        #      see 5.3.3.3, we maintain list of contexts we are in session
        #      with, if not in list, return CREDPROBLEM
        #      if security credentials expire, return CTXPROBLEM
        #   check header checksum in verf, failure returns CREDPROBLEM
        #   check seq_num in cred, silently drop repeats,
        #       return CTXPROBLEM if exceeds window
        #   check seq_num in data, return GARBAGE_ARGS if mismatches cred
        #   check gss_proc==DATA, else:
        #       if proc==0, handle elsewhere
        #       else return AUTH_BADCRED
        return True
    
    def connect(self, address, secure=False):
        """Connect to given address, returning new pipe

        If secure==True, will bind local asocket to a port < 1024.
        """
        log_t.info("Called connect(%r)" % (address,))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if secure:
            self.bindsocket(s)
        s.connect(address)
        s.setblocking(0)
        pipe = Pipe(s)
        # Tell polling loop about the new socket
        defer = DeferredData()
        self.socket_alarm.buzz((pipe, defer))
        # Wait until polling loop knows about new socket
        defer.wait()
        return pipe

    def bindsocket(self, s, port=0):
        """Scan up through ports, looking for one we can bind to"""
        # This is necessary when we need to use a 'secure' port
        using = port
        while 1:
            try:
                s.bind(('', using))
                return
            except socket.error, why:
                if why[0] == errno.EADDRINUSE:
                    using += 1
                    if port < 1024 <= using:
                        # If we ask for a secure port, make sure we don't
                        # silently bind to a non-secure one
                        raise
                else:
                    raise


    def expose(self, address, safe=True):
        """Start listening for incoming connections on the given address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(address)
        s.setblocking(0)
        s.listen(5)
        self.listeners.add(s.fileno()) # XXX BUG - never removed
        if safe:
            # Tell polling loop about the new socket
            defer = DeferredData()
            self.socket_alarm.buzz((s, defer))
            # Wait until polling loop knows about new socket
            defer.wait()
        else:
            # This should only be called before start is run
            self.readlist.add(s.fileno())
            self.errlist.add(s.fileno())
            # A list of all sockets we have open, indexed by fileno
            self.sockets[s.fileno()] = s
        return s
            
    def send_raw(self, pipe, msg, data=''):
        """Send raw data (using record marking) over pipe using given rpc_msg.
        """
        if msg.body.mtype == CALL:
            # Need to know where to store matching REPLY.
            # NOTE - need to ensure this is created before anyone can listen
            pipe.pending[msg.xid] = DeferredData(msg)
        p = FancyRPCPacker()
        p.pack_rpc_msg(msg)
        header = p.get_buffer()
        try:
            pipe.write_queue.appendleft(header + data)
        except TypeError:
            raise RPCError("Pipe is closed")
        self.write_alarm.buzz(pipe.fileno())

    def close(self, pipe):
        log_t.info("Called close() for %i" % pipe.fileno())
        pipe._close_lock.acquire()
        try:
            if pipe.write_queue.appendleft is None:
                raise RPCError("Pipe is already closed")
            # Solve any races by locking out further sends
            pipe.write_queue.appendleft = None
            # Prevent any more reads from coming in
            # pipe.shutdown(socket.SHUT_RD)
            # Now signal for a close once write_queue is flushed
            collections.deque.appendleft(pipe.write_queue, None)
            self.write_alarm.buzz(pipe.fileno())
        finally:
            pipe._close_lock.release()

    def send_call(self, pipe, procedure, data='', credinfo=None, program=None, version=None):
        if program is None: program = self.default_prog
        if version is None: version = self.default_vers
        if program is None or version is None:
            raise Exception("Badness")
        if credinfo is None:
            credinfo = self.default_cred
        # XXX What to do if cred not initialized?  Currently send_call
        # does not block, but the call to init_cred will block.  Apart
        # from that, this is a logical place to do the init.
        sec = credinfo.sec
        xid = pipe.get_xid()
        # Build header
        cred = sec.make_cred(credinfo)
        verf = None # This needs same info as body, easier to delay
        body = call_body(self.rpcversion, program, version, procedure,
                         cred, verf)
        body.verf = sec.make_call_verf(xid, body)
        msg = rpc_msg(xid, rpc_msg_body(CALL, body))
        msg.sec = sec # HACK to pass sec to reply handler
        # Wrap data
        data = sec.secure_data(cred, data)
        # Send it off
        self.send_raw(pipe, msg, data)
        return xid

    def make_call_function(self, pipe, procedure, prog, vers):
        def call(data, credinfo, proc=None, timeout=15.0):
            if proc is None:
                proc = procedure
            xid = self.send_call(pipe, proc, data, credinfo, prog, vers)
            header, data = pipe.listen(xid, timeout)
            # XXX STUB - do header checking
            return header, data
        return call
    
    def send_reply(self, pipe, xid, body, proc_response=""):
        log_t.debug("send_reply\nbody = %r\ndata=%r" % (body, proc_response))
        msg = rpc_msg(xid, rpc_msg_body(REPLY, rbody=body))
        self.send_raw(pipe, msg, proc_response)

    def listen(self, pipe, xid):
        # STUB - should be overwritten by subclass
        header, data = pipe.listen(xid)
        print "HEADER", header
        print "DATA", repr(data)

#################################################

class Server(ConnectionHandler):
    def __init__(self, prog, versions, port, interface=''):
        ConnectionHandler.__init__(self)
        self.prog = prog
        self.versions = versions # List of supported versions of prog
        self.rpcversion = 2
        self.security = {} # This need to be set somewhere/somehow
        # STUB
        self.security = {0: security.AuthNone(),
                         1: security.AuthSys(), #authsys_parms(3, "server",
                         #          0,0,[1,2,3,4])),
                         6: security.AuthGss(),
                         }
        
        self.default_cred = security.CredInfo()
        self.expose((interface, port), False)
        
class Client(ConnectionHandler):
    def __init__(self, program=None, version=None,
                 timeout=15.0, secureport=False, cb_version=1):
        ConnectionHandler.__init__(self)
        self.default_prog = program
        self.default_vers = version
        self.default_cred = security.CredInfo()
        self.timeout = timeout
        self.secureport = secureport
        self.rpcversion = 2
        self.prog = 0x40000000 # Callback handling prog #
        self.versions=[cb_version] # List of supported versions of CB server
        self.security = {0: security.AuthNone(),
                         1: security.AuthSys(), #authsys_parms(3, "server",
                         #          0,0,[1,2,3,4])),
                         6: security.AuthGss(),
                         }

        # Start polling
        t = threading.Thread(target=self.start, name="PollingThread")
        t.setDaemon(True)
        t.start()
        
    def check_reply(self, header):
        """Looks at rpc_msg reply and raises error if necessary

        xid has already been checked
        """
        # STUB - xid needs checking somewhere
        if header.mtype != REPLY:
            raise RPCError("Msg was not a REPLY")
        if header.stat == MSG_DENIED:
            # Do more here
            raise RPCDeniedError(header.rreply)
        elif header.rbody.reply_data.stat != SUCCESS:
            raise RPCAcceptError(header.areply)
        # STUB - need to check verifier, which requires more info
        pass

    def set_cred(self, credinfo):
        # Needed for credinfo
        # AUTH_NONE : None
        # AUTH_SYS  : uid, gid, name, stamp, gids
        # RPCSEC_GSS: target, source(username)=None, oid=None, pipe=None,
        #             service, qop
        
        # Needed for init
        # AUTH_NONE : None
        # AUTH_SYS  : uid, gid, name, stamp, gids
        # RPCSEC_GSS: target, source(username)=None, oid=None, pipe=None,
        #             service, qop

        # NOTE - XXX need to think through threading issues
        self.default_cred = credinfo

#################################################
    
if __name__ == "__main__":
    S = RPCServer(prog=2049, versions=[4], port=54321)
    S.run()
