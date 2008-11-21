from rpc_const import *
from rpc_type import *

class RPCReply(Exception):
    """Not really an error, but used abort processing and send a reply."""
    def __init__(self, accept=True, stat=SUCCESS, statdata=None,
                 msgdata='', drop=False, verf=None):
        self.accept = accept
        self.stat = stat
        self.statdata = statdata
        self.msgdata = msgdata
        self.drop = drop
        self.verf = verf

    def body(self, sec, cred):
        if not self.accept:
            if self.stat == RPC_MISMATCH:
                rreply = rejected_reply(self.stat,
                                        rpc_mismatch_info(*self.statdata))
            else:
                rreply = rejected_reply(self.stat, astat=self.statdata)
            return reply_body(MSG_DENIED, rreply=rreply), ''
        else:
            msg_data = ''
            if self.stat == SUCCESS:
                if sec is None:
                    # This can occur for example during gss_init
                    msg_data = self.msgdata
                else:
                    try:
                        msg_data = sec.secure_data(cred, self.msgdata)
                    except SecError:
                        # BUG - what to do here?
                        raise
                args={"results": ""} # Note msg_data must be appended later
            elif self.stat == PROG_MISMATCH:
                args={"mismatch_info": rpc_mismatch_info(*self.statdata)}
            else:
                args={}
            data = rpc_reply_data(self.stat, **args)
            if self.verf is None:
                verf = sec.make_reply_verf(cred, self.stat)
            else:
                verf = self.verf
            areply = accepted_reply(verf, data)
            return reply_body(MSG_ACCEPTED, areply=areply), msg_data

