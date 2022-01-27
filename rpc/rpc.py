from __future__ import with_statement
from __future__ import absolute_import

import socket, select
import struct
import threading
import logging
from collections import deque as Deque
from errno import EINPROGRESS, EWOULDBLOCK

from . import rpc_pack
from .rpc_const import *
from .rpc_type import *

from . import security
from . import rpclib
import random

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
    """Wait for data to arrive.

    Thread 1 does:
    defer = DeferredData()
    start_another_thread(defer)
    defer.wait()
    # Now data field is accessible or exception has been raised

    Thread 2 does:
    # Access defer.msg if needed
    defer.fill()
    # Thread should no longer reference defer
    """
    def __init__(self, msg=None):
        self._filled = threading.Event()
        self.data = None
        self._exception = None
        self.msg = msg # Data that thread calling fill might need

    def wait(self, timeout=300):
        """Wait for data to be filled in"""
        self._filled.wait(timeout)
        if not self._filled.isSet():
            raise RPCTimeout
        if self._exception is not None:
            raise self._exception

    def fill(self, data=None, exception=None):
        """Fill with data, and flag that this has been done.

        Caller should no longer reference the object afterwards.
        """
        self._exception = exception
        self.data = data
        self._filled.set()

class Alarm(object):
    """A method of notifying select loop that there is data waiting"""
    def __init__(self, address):
        self._queue = Deque()
        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.setblocking(0)
        try:
            self._s.connect(address)
        except socket.error as e:
            if e.args[0] in [EINPROGRESS, EWOULDBLOCK]:
                # address has not yet called accept, since this is done in a
                # single thread, so get "op in progress error".  When the
                # receiving end calls accept, all is good.
                pass
            else:
                raise

    def buzz(self, command, info):
        """Wake the polling loop, passing it info"""
        self._queue.appendleft(info)
        # Send one byte of data 'command' to wake select loop
        # Note bytes sent are counted to determine how many items to pop
        while (not self._s.send(command)):
            # Just loop here until we actually send something
            pass

    def pop(self):
        """Called by polling loop to grab the info passed in by buzz"""
        return self._queue.pop()

    def __getattr__(self, attr):
        """Show socket interface"""
        return getattr(self._s, attr)

class Pipe(object):
    """Groups a socket with its buffers.

    We deal with records, packets, and bytes.

    Records are the actual message strings that we want to send through the
    pipe.  Records go in one end and come out the other.  However, because
    all that *really* goes through is a stream of bytes, just sending the
    records as is wouldn't work, since there would be no way to tell where
    one record ends and another begins.

    So record marking is used (rfc 1831 section 10), which breaks the
    record into packets (called record fragments in the rfc), and precedes
    each packet with a byte count and an end-of-record flag.

    The raw byte stream sent is thus the packets with the interspersed
    accounting information.

    The general flow here is as follows:

    server
    The polling thread notices the Pipe has data waiting to be read.
    So it calls recv_records, which reads the raw data and returns records.
    The polling thread hands each record off to a worker thread.  That
    thread, if it wishes to reply, calls push_record. This notifies the
    polling thread, which calls pop_record to prepare for flush_pipe.

    client
    The client calls push_record, creates a DeferredData instance
    associated with the xid, and calls its wait method.
    Push_record notifies the polling thread, which calls pop_record to
    prepare for flush_pipe, sending the call to the server.
    Eventually the polling thread notices the Pipe has data waiting to be
    read (a server reply), so it calls recv_records, which reads the raw data
    and returns a record, which is eventually dumped into the DeferredData
    structure via fill(), waking the original client thread
    """
    def __init__(self, socket, write_alarm):
        self._s = socket
        # Note the write queue is accessed by both main and worker threads,
        # so uses thread-safe deque() struture.  The other buffers are only
        # looked at by the main thread, so no locking is required.
        self._write_queue = Deque() # Records waiting to be sent out
        self._alarm = write_alarm # Way to notify we have data to write
        self._write_buf = b'' # Raw outgoing data
        self._read_buf = b'' # Raw incoming data
        self._packet_buf = [] # Store packets read until have a whole record

    def __getattr__(self, attr):
        """Show socket interface"""
        return getattr(self._s, attr)

    def __str__(self):
        return "pipe-%i" % self._s.fileno()

    def recv_records(self, count):
        """Pull up to count bytes from pipe, converting into records."""
        # This is only called from main handler thread, so doesn't need locking
        data = self._s.recv(count)
        if not data:
            # This indicates socket has closed
            return None
        out = []
        self._read_buf += data
        while self._read_buf:
            buf = self._read_buf
            if len(buf) < 4:
                # We don't even have the packet length yet, wait for more data
                break
            packetlen = struct.unpack('>L', buf[0:4])[0]
            last = 0x80000000 & packetlen
            packetlen &= 0x7fffffff
            packetlen += 4 # Include size of record mark
            if len(buf) < packetlen:
                # We don't have a full packet yet, wait for more data
                break
            self._packet_buf.append(buf[4:packetlen])
            self._read_buf = buf[packetlen:]
            if last:
                # We have a full RPC record.  Note this does not imply that
                # self._read_buf is empty.
                record = b''.join(self._packet_buf)
                self._packet_buf = []
                out.append(record)
        return out

    def push_record(self, record):
        """Prepares handler thread to send record.

        If None is sent, no further data will be accepted, and pipe will be
        closed once previous data is flushed.
        """
        # This is called from worker threads, so needs locking.
        # However, deque is thread safe, so all is good
        self._write_queue.appendleft(record)
        # Notify ConnectionHandler that there is data to write
        self._alarm.buzz(b'\x00', self)

    def pop_record(self, count):
        """Pulls record off stack and places in write buffer.

        Appropriate record marking is added.  This should be called once
        for each push_record called.  This is handled by arranging to have
        the function called each time the the polling loop responds to
        self._alarm.buzz.
        """
        def add_record_marks(record, count):
            """Given a record, convert it to actual stream to send over TCP"""
            dlen = len(record)
            i = last = 0
            out = b'' # FRED - use stringio here?
            while not last:
                chunk = record[i: i + count]
                i += count
                if i >= dlen:
                    last = 0x80000000
                mark = struct.pack('>L', last | len(chunk))
                out += mark + chunk
            return out

        record = self._write_queue.pop()
        self._write_buf += add_record_marks(record, count)

    def flush_pipe(self):
        """Try to flush the write buffer.

        Return True if succeeds, False if needs to be called again.

        Note this only flushes the buffer of raw bytes waiting to be sent.
        It does not look at the waiting stack of non-marked records.
        """
        if not self._write_buf:
            raise RuntimeError
        try:
            count = self._s.send(self._write_buf)
        except socket.error as e:
            log_p.error("flush_pipe got exception %s" % str(e))
            return True # This is to stop retries
        self._write_buf = self._write_buf[count:]
        return (not self._write_buf)

class RpcPipe(Pipe):
    """Hide pipe related xid handling.

    The expected use is for a client thread to do:
            xid = pipe.send_call()
            reply = pipe.listen(xid)
    A server thread will just do:
            pipe.send_reply()
    """
    rpcversion = 2 # The RPC version that is used by default

    def __init__(self, *args, **kwargs):
        Pipe.__init__(self, *args, **kwargs)
        self._pending = {} # {xid:defer}
        self._lock = threading.Lock() # Protects fields below
        self._xid = random.randint(0, 0x7fffffff)
        self.set_active()

    def _get_xid(self):
        with self._lock:
            out = self._xid
            self._xid = inc_u32(out)
        return out

    def set_active(self):
        self._active = True

    def clear_active(self):
        self._active = False

    def is_active(self):
        return self._active

    def listen(self, xid, timeout=None):
        """Wait for a reply to a CALL."""
        self._pending[xid].wait(timeout)
        reply = self._pending[xid].data # This is set at end of self.rcv_reply
        del self._pending[xid]
        return reply

    def rpc_send(self, rpc_msg, data=b''):
        """Send raw data over pipe using given rpc_msg"""
        p = FancyRPCPacker()
        p.pack_rpc_msg(rpc_msg)
        header = p.get_buffer()
        self.push_record(header + data)

    def send_reply(self, xid, body, proc_response=""):
        log_t.debug("send_reply\nbody = %r\ndata=%r" % (body, proc_response))
        msg = rpc_msg(xid, rpc_msg_body(REPLY, rbody=body))
        self.rpc_send(msg, proc_response)

    def send_call(self, program, version, procedure, data, credinfo):
        """Send a CALL, and store info needed to match and verify reply."""
        sec = credinfo.sec
        cred = sec.make_cred(credinfo)
        body = call_body(self.rpcversion, program, version, procedure,
                         cred, None)
        xid = self._get_xid()
        body.verf = sec.make_call_verf(xid, body)
        msg = rpc_msg(xid, rpc_msg_body(CALL, body))
        data = sec.secure_data(cred, data)
        # Store info needed be receiving thread to match and verify reply
        self._pending[xid] = DeferredData((cred, sec))
        self.rpc_send(msg, data)
        return xid

    def rcv_reply(self, msg, msg_data):
        """Do sec handling of reply, then hand it off to matching call event."""
        try:
            # This should match a CALL made with self.send_call
            deferred = self._pending[msg.xid]
        except IndexError:
            log_t.warn("Reply with unexpected xid=%i" % msg.xid)
            raise
        exc = None # Exception that will be raised in calling thread
        cred, sec = deferred.msg # This was set in self.send_call()
        try:
            sec.check_reply_verf(msg, cred, msg_data)
        except Exception:
            log_t.warn("Reply did not pass verifier checks", exc_info=True)
            raise
        if msg.stat == MSG_DENIED:
            exc = RPCDeniedError(msg.rreply)
        elif msg.reply_data.stat != SUCCESS:
            exc = RPCAcceptError(msg.areply)
        else:
            try:
                msg_data = sec.unsecure_data(cred, msg_data)
            except Exception:
                # Unsure what to do here.
                # FRED - what is the point of verifier, if this can occur?
                exc = RPCError("Failed to unsecure data in reply")
        log_t.debug("Filling deferral %i" % msg.xid)
        reply = (msg, msg_data) # The return value of self.listen()
        deferred.fill(reply, exc)

#################################################

class ConnectionHandler(object):
    """Common code for server and client.

    Sets up polling and event dispatching, and deals with RPC headers, xids,
    and record marking in the communication streams.

    NOTE that the _event_* functions should not be called directly,
    but only through start.  Thread safety depends on this.
    """
    def __init__(self):
        self._stopped = False
        # Set up polling lists
        self.readlist = set()
        self.writelist = set()
        self.errlist = set()
        # A list of all sockets we have open, indexed by fileno
        self.sockets = {} # {fd: pipe}
        # A list of the sockets set to listen for connections
        self.listeners = set()

        # Create internal server for alarm system to connect to
        self.s = self.expose((LOOPBACK, 0), socket.AF_INET, False)

        # Set up alarm system, which is how other threads inform the polling
        # thread that data is ready to be sent out
        # NOTE that there are TWO sockets associated with alarm, one
        # for each end of the connection.  Nasty bugs creep in here.
        self._alarm = Alarm(self.s.getsockname())
        self._alarm_poll = self._event_connect_incoming(self.s.fileno(),
                                                        internal=True)

        # Set up some constants that effect general behavior
        self.rsize = 4096 # Read data in chunks of this size
        self.wsize = 4098 # Read data in chunks of this size
        self.rpcversions = (2,) # Supported RPC versions

        # Dictionary {flavor: handler} used for server-side authentication
        self.sec_flavors = security.instances()

    def _buzz_write_ready(self, pipe):
        """Pipe has data ready to be sent out"""
        pipe.pop_record(self.wsize)
        self.writelist.add(pipe.fileno())

    def _buzz_new_socket(self, data):
        """A new socket needs to be added"""
        pipe, defer = data
        fd = pipe.fileno()
        log_p.info("Adding %i generated by another thread" % fd)
        # Add to known connections
        self.sockets[fd] = pipe
        # Start listening on new connection
        self.readlist.add(fd)
        self.errlist.add(fd)
        # Notify thread which created connection that it is now up
        defer.fill()

    def _buzz_stop(self, data):
        """We want to exit the start loop"""
        self._stopped = True

    def start(self):
        switch = {0 : self._buzz_write_ready,
                  1 : self._buzz_new_socket,
                  2 : self._buzz_stop,
                  }
        while not self._stopped:
            log_p.debug("Calling select")
            log_p.log(5, "Sleeping for: %s, %s, %s" %
                 (self.readlist, self.writelist, self.errlist))
            r,w,e = select.select(self.readlist, self.writelist, self.errlist)
            log_p.log(5, "Woke with: %s, %s, %s" % (r, w, e))
            for fd in e:
                log_p.warn(1, "polling error from %i" % fd)
                # STUB - now what?
            for fd in w:
                try:
                    self._event_write(fd)
                except socket.error as e:
                    self._event_close(fd)
            for fd in r:
                if fd in self.listeners:
                    try:
                        self._event_connect_incoming(fd)
                    except socket.error as e:
                        self._event_close(fd)
                elif fd == self._alarm_poll.fileno():
                    commands = self._alarm_poll.recv(self.rsize)
                    for c in commands:
                        data = self._alarm.pop()
                        try:
                            switch[c](data)
                        except socket.error as e:
                            self._event_close(fd)
                else:
                    try:
                        data = self.sockets[fd].recv_records(self.rsize)
                    except socket.error:
                        data = None
                    if data is not None:
                        self._event_read(data, fd)
                    else:
                        self._event_close(fd)
        for s in self.sockets.values():
            s.close()

    def stop(self):
        self._alarm.buzz(b'\x02', None)

    def _event_connect_incoming(self, fd, internal=False):
        """Someone else is trying to connect to us (we act like server)."""
        s = self.sockets[fd]
        try:
            if internal:
                # We are accepting from the same thread that tried to connect.
                # In linux this works, but in Windows it raises EWOULDBLOCK
                # if we don't do this
                s.setblocking(1)
                csock, caddr = s.accept()
                s.setblocking(0)
            else:
                csock, caddr = s.accept()
        except socket.error as e:
            log_p.error("accept() got error %s" % str(e))
            return
        csock.setblocking(0)
        fd = csock.fileno()
        pipe = self.sockets[fd] = RpcPipe(csock, self._alarm)
        log_p.info("got connection from %s, assigned to fd=%i" %
             (csock.getpeername(), fd))
        # Start listening for data to come in on new connection
        self.readlist.add(fd)
        self.errlist.add(fd)
        return pipe

    def _event_close(self, fd):
        """Close the connection, and remove references to it."""
        log_p.info("Closing %i" % fd)
        temp = set([fd])
        self.writelist -= temp
        self.readlist -= temp
        self.errlist -= temp
        self.sockets[fd].clear_active()
        self.sockets[fd].close()
        del self.sockets[fd]

    def _event_write(self, fd):
        """Data is waiting to be written."""
        if self.sockets[fd].flush_pipe():
            self.writelist.remove(fd)
            log_p.log(5, "Finished writing to %i" % fd)

    def _event_read(self, records, fd):
        """Data is waiting to be read.

        For each full RPC record, then dispatch it to a thread.
        """
        s = self.sockets[fd]
        for r in records:
            log_p.log(5, "Received record from %i" % fd)
            log_p.log(2, repr(r))
            t = threading.Thread(target=self._event_rpc_record, args=(r, s))
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
            # Remember length of the header
            msg.length = p.get_position()
        except (rpc_pack.XDRError, EOFError) as e:
            log_t.warn("XDRError: %s, dropping packet" % e)
            log_t.debug("unpacking raised the following error", exc_info=True)
            self._notify_drop()
            return # Drop incorrectly encoded packets
        log_t.debug("MSG = %s" % str(msg))
        log_t.debug("data = %r" % msg_data)
        if msg.mtype == REPLY:
            self._event_rpc_reply(msg, msg_data, pipe)
        elif msg.mtype == CALL:
            self._event_rpc_call(msg, msg_data, pipe)
        else:
            # Shouldn't get here, but doesn't hurt
            log_t.error("Received rpc_record with msg.type=%i" % msg.type)
            self._notify_drop()

    def _event_rpc_reply(self, msg, msg_data, pipe):
        """Deal with an incoming RPC REPLY.

        msg is unpacked header,
        msg_data is raw procedure data.
        """
        try:
            pipe.rcv_reply(msg, msg_data)
        except Exception:
            self._notify_drop()

    def _event_rpc_call(self, msg, msg_data, pipe):
        """Deal with an incoming RPC CALL.

        msg is unpacked header, with length fields added.
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
        call_info.connection = pipe
        call_info.raw_cred = msg.body.cred
        notify = None
        try:
            # Check for reasons to DENY the call
            try:
                self._check_rpcvers(msg)
                call_info.credinfo = self._check_auth(msg, msg_data)
            except rpclib.RPCFlowContol:
                raise
            except Exception:
                log_t.warn("Problem with incoming call, returning AUTH_FAILED",
                           exc_info=True)
                raise rpclib.RPCDeniedReply(AUTH_ERROR, AUTH_FAILED)
            # Call has been ACCEPTED, now check for reasons not to succeed
            sec = call_info.credinfo.sec
            msg_data = sec.unsecure_data(msg.body.cred, msg_data)
            if not self._check_program(msg.prog):
                log_t.warn("PROG_UNAVAIL, do not support prog=%i" % msg.prog)
                raise rpclib.RPCUnsuccessfulReply(PROG_UNAVAIL)
            low, hi = self._version_range(msg.prog)
            if not self._check_version(low, hi, msg.vers):
                log_t.warn("PROG_MISMATCH, do not support vers=%i" % msg.vers)
                raise rpclib.RPCUnsuccessfulReply(PROG_MISMATCH, (low, hi))
            method = self._find_method(msg)
            if method is None:
                log_t.warn("PROC_UNAVAIL for vers=%i, proc=%i" %
                           (msg.vers, msg.proc))
                raise rpclib.RPCUnsuccessfulReply(PROC_UNAVAIL)
            # Everything looks good at this layer, time to do the call
            tuple = method(msg_data, call_info)
            if len(tuple) == 2:
                status, result = tuple
            else:
                status, result, notify = tuple
            if result is None:
                result = b''
            if isinstance(result, str):
                result = bytes(result, encoding='UTF-8')

            if not isinstance(result, bytes):
                raise TypeError("Expected bytes, got %s" % type(result))
            # status, result = method(msg_data, call_info)
            log_t.debug("Called method, got %r, %r" % (status, result))
        except rpclib.RPCDrop:
            # Silently drop the request
            self._notify_drop()
            return
        except rpclib.RPCFlowContol as e:
            body, data = e.body()
        except Exception:
            log_t.warn("Unexpected exception", exc_info=True)
            body, data = rpclib.RPCUnsuccessfulReply(SYSTEM_ERR).body()
        else:
            try:
                data = sec.secure_data(msg.body.cred, result)
                verf = sec.make_reply_verf(msg.body.cred, status)
                areply = accepted_reply(verf, rpc_reply_data(status, b''))
                body = reply_body(MSG_ACCEPTED, areply=areply)
            except Exception:
                body, data = rpclib.RPCUnsuccessfulReply(SYSTEM_ERR).body()
        pipe.send_reply(msg.xid, body, data)
        if notify is not None:
            notify()

    def _notify_drop(self):
        """Debugging hook called when a request is dropped."""
        log_t.warn("Dropped request")

    def _find_method(self, msg):
        """Returns function that should handle an incoming call.

        Returns None if no handler can be found.
        Needs to be implemented by subclass if will be used as server.
        """
        raise NotImplementedError

    def _version_range(self, prog):
        """Returns pair of min and max supported versions for given program.

        We assume that all versions between min and max ARE supported.
        Needs to be implemented by subclass if will be used as server.
        """
        raise NotImplementedError

    def _check_program(self, prog):
        """Returns True if call program is supported, False otherwise.

        Needs to be implemented by subclass if will be used as server.
        """
        raise NotImplementedError

    def _check_rpcvers(self, msg):
        """Returns True if rpcvers is ok, otherwise sends out MSG_DENIED"""
        if msg.rpcvers not in self.rpcversions:
            log_t.warn("RPC_MISMATCH, do not support vers=%i" % msg.rpcvers)
            raise rpclib.RPCDeniedReply(RPC_MISMATCH,
                                        (min(self.rpcversions),
                                         max(self.rpcversions)))

    def _check_auth(self, msg, data):
        """Returns security module to use if call processing should continue,

        otherwise returns None.
        Note that it is possible for security module to hijack call processing.
        """
        # Check that flavor is supported
        try:
            sec = self.sec_flavors[msg.cred.flavor]
        except KeyError:
            log_t.warn("AUTH_ERROR: Unsupported flavor %i" % msg.cred.flavor)
            if msg.proc == 0 and msg.cred.flavor == AUTH_NONE:
                # RFC 1831 section 11.1 says "by convention" should allow this
                log_t.warn("Allowing NULL proc through anyway")
                sec = security.klass(AUTH_NONE)()
            else:
                raise rpclib.RPCDeniedReply(AUTH_ERROR, AUTH_FAILED)
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
        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, cannonname, sa = res
            sock = None
            try:
                s = socket.socket(af, socktype, proto)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if secure:
                    self.bindsocket(s)
                s.connect(sa)
                err = None
                break
            except:
                if s is not None:
                    s.close()

        s.setblocking(0)
        pipe = RpcPipe(s, self._alarm)
        # Tell polling loop about the new socket
        defer = DeferredData()
        self._alarm.buzz(b'\x01', (pipe, defer))
        # Wait until polling loop knows about new socket
        defer.wait()
        return pipe

    def bindsocket(self, s, port=1):
        """Scan up through ports, looking for one we can bind to"""
        # This is necessary when we need to use a 'secure' port
        using = port
        while 1:
            try:
                s.bind(('', using))
                return
            except socket.error as why:
                if why[0] == errno.EADDRINUSE:
                    using += 1
                    if port < 1024 <= using:
                        # If we ask for a secure port, make sure we don't
                        # silently bind to a non-secure one
                        raise
                else:
                    raise


    def expose(self, address, af, safe=True):
        """Start listening for incoming connections on the given address"""
        s = socket.socket(af, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(address)
        s.setblocking(0)
        s.listen(5)
        self.listeners.add(s.fileno()) # XXX BUG - never removed
        if safe:
            # Tell polling loop about the new socket
            defer = DeferredData()
            self._alarm.buzz('\x01', (s, defer))
            # Wait until polling loop knows about new socket
            defer.wait()
        else:
            # This should only be called before start is run
            self.readlist.add(s.fileno())
            self.errlist.add(s.fileno())
            # A list of all sockets we have open, indexed by fileno
            self.sockets[s.fileno()] = s
        return s

    def make_call_function(self, pipe, procedure, prog, vers):
        def call(data, credinfo, proc=None, timeout=300):
            if proc is None:
                proc = procedure
            xid = self.send_call(pipe, proc, data, credinfo, prog, vers)
            header, data = pipe.listen(xid, timeout)
            # XXX STUB - do header checking
            return header, data
        return call

    def listen(self, pipe, xid):
        # STUB - should be overwritten by subclass
        header, data = pipe.listen(xid)
        print("HEADER", header)
        print("DATA", repr(data))

#################################################

class Server(ConnectionHandler):
    def __init__(self, prog, versions, port, interface=''):
        ConnectionHandler.__init__(self)
        self.prog = prog
        self.versions = versions # List of supported versions of prog
        self.default_cred = security.CredInfo()
        try:
            # This listens on both AF_INET and AF_INET6
            self.expose((interface, port), socket.AF_INET6, False)
        except:
            # ipv6 not supported, fall back to ipv4
            self.expose((interface, port), socket.AF_INET, False)

    def _check_program(self, prog):
        return (self.prog == prog)

    def _check_version(self, low, hi, vers):
        return (low <= vers <= hi)

    def _version_range(self, prog):
        return (min(self.versions), max(self.versions))

    def _find_method(self, msg):
        method = getattr(self, 'handle_%i' % msg.proc, None)
        if method is not None:
            return method
        method = getattr(self, 'handle_%i_v%i' % (msg.proc, msg.vers), None)
        return method

class Client(ConnectionHandler):
    def __init__(self, program=None, version=None, secureport=False):
        ConnectionHandler.__init__(self)
        self.default_prog = program
        self.default_vers = version
        self.default_cred = security.CredInfo()
        self.secureport = secureport

        # Start polling
        t = threading.Thread(target=self.start, name="PollingThread")
        t.setDaemon(True)
        t.start()

    def send_call(self, pipe, procedure, data=b'', credinfo=None,
                  program=None, version=None):
        if program is None: program = self.default_prog
        if version is None: version = self.default_vers
        if program is None or version is None:
            raise Exception("Badness")
        if credinfo is None:
            credinfo = self.default_cred
        # XXX What to do if cred not initialized?  Currently send_call
        # does not block, but the call to init_cred will block.  Apart
        # from that, this is a logical place to do the init.
        return pipe.send_call(program, version, procedure, data, credinfo)

#################################################
