from nfs4_type import server_owner4, nfs_impl_id4
from nfs4_const import *
import nfs4_const
import nfs4lib
from copy import deepcopy

class ConfigAction(Exception):
    pass

def _action(value):
    raise ConfigAction

def _int(value):
    return int(value)

def _bool(value):
    if type(value) is str:
        value = value.lower()
        if value == "true":
            return True
        elif value == "false":
            return False
        else:
            return bool(int(value))
    else:
        return bool(value)

def _statcode(value):
    try:
        return int(value)
    except ValueError:
        rv = getattr(nfs4_const, value, None)
        if rv is None or nfsstat4.get(rv, None) != value:
            raise
        else:
            return rv

class ConfigLine(object):
    def _set_value(self, value):
        try:
            self._value = self.verify(value)
        except ConfigAction, e:
            e.name = self.name
            e.value = value
            raise
    value = property(lambda s: s._value, _set_value)
    def __init__(self, name, value, comment, verifier=None):
        if verifier is None:
            # Set default verifier to int or bool based on initial value
            if type(value) is bool:
                verifier = _bool
            else:
                verifier = _int
        self.name = name
        self._value = value
        self.comment = comment
        self.verify = verifier # value = self.verify(value)

class MetaConfig(type):
    def __init__(cls, name, bases, dict):
        def make_set(i):
            def set(self, value):
                self.attrs[i].value = value
            return set
        def make_get(i):
            def get(self):
                return self.attrs[i].value
            return get
        def make_init(attrs, orig_init):
            def init(self, *args, **kwargs):
                self.attrs = deepcopy(attrs)
                if orig_init is not None:
                    orig_init(self, *args, **kwargs)
            return init
        # We expect a list of ConfigLine in attrs
        attrs = dict.pop("attrs")
        # Remove attrs from cls.__dict__ and put in self.__dict__
        super(MetaConfig, cls).__init__(name, bases, dict)
        cls.__init__ = make_init(attrs, dict.get("__init__", None))
        # Turn each attr into a property
        for i, attr in enumerate(attrs):
            setattr(cls, attr.name, property(make_get(i), make_set(i),
                                             None, attr.comment))
        
class ServerConfig(object):
    __metaclass__ = MetaConfig
    attrs =  [ConfigLine("allow_null_data", False,
                         "Server allows NULL calls to contain data"),
              ConfigLine("tag_info", True,
                         "Server sends debug info in reply tags"),
              ConfigLine("lease_time", 60,
                         "Server lease time in seconds"),
              ConfigLine("catch_ctrlc", True,
                         "Ctrl-c sends server into interactive debugging shell"),
              ]

    def __init__(self):
        self.minor_id = 0
        self.major_id = "PyNFSv4.1"
        self._owner = server_owner4(self.minor_id, self.major_id)
        self.scope = "Default_Scope"
        self.impl_domain = "citi.umich.edu"
        self.impl_name = "pynfs X.X"
        self.impl_date = 1172852767 # int(time.time())
        self.impl_id = nfs_impl_id4(self.impl_domain, self.impl_name,
                                 nfs4lib.get_nfstime(self.impl_date))

class ServerPerClientConfig(object):
    __metaclass__ = MetaConfig
    attrs = [ConfigLine("maxrequestsize", 16384,
                        "Maximum request size the server will accept"),
             ConfigLine("maxresponsesize", 16384,
                        "Maximum response size the server will send"),
             ConfigLine("maxresponsesize_cached", 4096,
                        "Maximum response size the server will cache"),
             ConfigLine("maxoperations", 128,
                        "Max number of ops/compound the server accepts"),
             ConfigLine("maxrequests", 8,
                        "Max number of slots/session the server accepts"),
             ConfigLine("allow_bind_both", True,
                        "Server will bind both channels at once?"),
             ConfigLine("allow_stateid1", True,
                        "Server allows READ to bypass lock checks?"),
             ConfigLine("allow_close_with_locks", False,
                        "Server will automatically release any locks held before executing CLOSE"),
             ConfigLine("debug_state", False,
                        "Turns on some debug printing related to client.state dictionary"),
             ]

# These are the only ops that can occur within a compound before session
# (and thus client) is known.
_valid_server_ops = [
    OP_SEQUENCE, OP_BIND_CONN_TO_SESSION, OP_EXCHANGE_ID,
    OP_CREATE_SESSION, OP_DESTROY_SESSION,
    ]

# These ops aren't valid, so shouldn't be set
_invalid_ops = [
    OP_OPEN_CONFIRM, OP_RENEW, OP_SETCLIENTID, OP_SETCLIENTID_CONFIRM,
    OP_RELEASE_LOCKOWNER, OP_ILLEGAL,
    ]

class OpsConfigServer(object):
    __metaclass__ = MetaConfig
    attrs = [ConfigLine(name.lower()[3:], 0, "Generic comment", _statcode)
             for name in nfs_opnum4.values()]

class OpsConfigClient(object):
    __metaclass__ = MetaConfig
    attrs = [ConfigLine(name.lower()[3:], 0, "Generic comment", _statcode)
             for name in nfs_opnum4.values()]

class Actions(object):
    __metaclass__ = MetaConfig
    attrs = [ConfigLine("reboot", 0,
                        "Any write here will simulate a server reboot",
                        _action),
             ]
