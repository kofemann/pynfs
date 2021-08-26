from .rpc_const import *
from .rpc_type import *

import logging
log = logging.getLogger("rpc.lib")

NULL_CRED = opaque_auth(AUTH_NONE, b'')

class RPCFlowContol(Exception):
    """Used to initiate unusual flow control changes.

    Should always be caught, and not be propagated out of rpc code.
    """
    pass

class RPCDrop(RPCFlowContol):
    """Stop processing incoming record and kill the worker thread."""
    pass

class RPCDeniedReply(RPCFlowContol):
    """Stop processing incoming record and send a reply."""
    def __init__(self, stat, statdata=None):
        self.stat = stat
        self.statdata = statdata

    def body(self): # STUB - need better name for method
        try:
            if self.stat == RPC_MISMATCH:
                rreply = rejected_reply(self.stat,
                                        rpc_mismatch_info(*self.statdata))
            elif self.stat == AUTH_ERROR and self.statdata is not None:
                rreply = rejected_reply(self.stat, astat=self.statdata)
            else:
                # Something has gone haywire
                rreply = rejected_reply(AUTH_ERROR, astat=AUTH_FAILED)
        except Exception as e:
            log.critical("Oops, encountered bug", exc_info=True)
            rreply = rejected_reply(AUTH_ERROR, astat=AUTH_FAILED)
        return reply_body(MSG_DENIED, rreply=rreply), b''

class RPCUnsuccessfulReply(RPCFlowContol):
    """Stop processing incoming record and send a reply."""
    def __init__(self, stat, statdata=None):
        self.stat = stat
        self.statdata = statdata

    def body(self):
        try:
            if self.stat == SUCCESS or self.stat not in accept_stat:
                data = rpc_reply_data(SYSTEM_ERR)
            else:
                data = rpc_reply_data(self.stat)
            if self.stat == PROG_MISMATCH:
                data.mismatch_info = rpc_mismatch_info(*self.statdata)
        except Exception as e:
            log.critical("Oops, encountered bug", exc_info=True)
            data = rpc_reply_data(SYSTEM_ERR)
        areply = accepted_reply(NULL_CRED, data)
        return reply_body(MSG_ACCEPTED, areply=areply), b''

class RPCSuccessfulReply(RPCFlowContol):
    """Stop processing incoming record and send a reply."""
    def __init__(self, verf, msgdata=b''):
        self.msgdata = msgdata
        self.verf = verf

    def body(self):
        args={"results": b""} # Note msg_data must be appended later
        data = rpc_reply_data(SUCCESS, results=b"")
        areply = accepted_reply(self.verf, data)
        return reply_body(MSG_ACCEPTED, areply=areply), self.msgdata
