
import random

class Errors:

    def __init__(self):
        random.seed()

    # ERROR FUNCTIONS
    def short_read(self, opname, arg, env=None):
        arg.opread.count = random.randint(0, arg.opread.count)

    def wrong_offset(self, opname, arg, env=None):
        arg.opread.offset = random.randint(arg.offset + 1,
                                           arg.offset + arg.count)

    def wrong_sequenceid(self, opname, arg, env=None):
        arg.sa_sequenceid = int(arg.sa_sequenceid) - 1

    # ERROR SCENARIOS
