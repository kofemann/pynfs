from rpc.rpc_const import AUTH_NONE
from rpc.rpc_type import opaque_auth

class SecError(Exception):
    pass

class SecFlavor(object):
    _none = opaque_auth(AUTH_NONE, b'')
    
    def initialize(self, client):
        pass

    def secure_data(self, data, cred):
        """Add any security info/encryption to procedure arg/res
        'data' is the data stream that would be sent if there were no security
        'cred' is the opaque_auth structure that will be sent in header
        """
        return data

    def unsecure_data(self, data, cred):
        """Remove any security cruft from procedure arg/res
        'data' is the received security wrapped data stream
        'cred' is the opaque_auth structure received in header
        """
        return data

    def make_cred(self):
        """Credential sent with each RPC call"""
        return self._none

    def make_verf(self, data):
        """Verifier sent with each RPC call

        'data' is packed header upto and including cred
        """
        return self._none

    def make_reply_verf(self, cred, stat):
        """Verifier sent by server with each RPC reply"""
        return self._none

    def get_owner(self):
        """Return uid"""
        return 0

    def get_group(self):
        """Return gid"""
        return 0

    def check_verf(self, rverf, cred):
        """Raise error if there is a problem with reply verifier"""
        pass
