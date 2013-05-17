from nfs4_const import *
import nfs4_ops as op
from environment import check, fail
from nfs4_type import *
import random
import nfs4lib
import threading

def testTwoSessions(t, env):
	"""Create multiple sessions per client

	FLAGS: trunking all
	CODE: TRUNK1
	"""
	c = env.c1.new_client(env.testname(t))
	sess = c.create_session()
	sess2 = c.create_session()


def testUseTwoSessions(t, env):
	"""Use multiple sessions per client

	FLAGS: trunking all
	CODE: TRUNK2
	"""
	c = env.c1.new_client(env.testname(t))
	sess = c.create_session()
	res = sess.compound([])
	check(res)
	sess2 = c.create_session()
	res = sess2.compound([])
	check(res)
	res = c.c.compound([op.destroy_session(sess.sessionid)])
	check(res)
	res = sess2.compound([])
	check(res)

# create client
# create session
# send rpc
# create second session
# send rpc
# destroy first session
# send rpc
# destroy second session

# create client
# create session
# destroy session
# later: check that callback channel now marked as down.
# create another session
# trigger callback, check that it occurred.

# more advanced: as in 4.0 test: trigger callback first, ignore it,
# then create another session.

# Or: create multiple sessions, destroy one-by-one, till down
# to one that wasn't original session, check that callbacks work
# throughout.

# repeat all above, with multiple connections/session instead of
# sessions/clientid

# Also try sending requests across multiple sessions, make sure sequence
# numbers are handled right, make sure sequence numbers of backchannel
# are handled right, etc.

