typedef int			int32_t;
typedef unsigned int		uint32_t;
typedef opaque                  str<>;

enum ctrl_opnum {
	CTRL_RESET   = 1,
	CTRL_RECORD  = 2,
	CTRL_PAUSE   = 3,
	CTRL_GRAB    = 4,
	CTRL_ILLEGAL = 1234
};

enum stat_t {
	CTRLSTAT_OK          = 0,
	CTRLSTAT_NOT_AVAIL   = 1,
	CTRLSTAT_SERVERFAULT = 2,
        CTRLSTAT_ILLEGAL     = 1000
};

enum dir_t {
	DIR_NONE  = 0,
	DIR_CALL  = 1,
	DIR_REPLY = 2,
	DIR_BOTH  = 3
};

enum nfs_opnum4 {
	OP_ACCESS		= 3,
	OP_CLOSE		= 4,
	OP_COMMIT		= 5,
	OP_CREATE		= 6,
	OP_DELEGPURGE		= 7,
	OP_DELEGRETURN		= 8,
	OP_GETATTR		= 9,
	OP_GETFH		= 10,
	OP_LINK			= 11,
	OP_LOCK			= 12,
	OP_LOCKT		= 13,
	OP_LOCKU		= 14,
	OP_LOOKUP		= 15,
	OP_LOOKUPP		= 16,
	OP_NVERIFY		= 17,
	OP_OPEN			= 18,
	OP_OPENATTR		= 19,
	OP_OPEN_CONFIRM		= 20, /* Mandatory not-to-implement */
	OP_OPEN_DOWNGRADE	= 21,
	OP_PUTFH		= 22,
	OP_PUTPUBFH		= 23,
	OP_PUTROOTFH		= 24,
	OP_READ			= 25,
	OP_READDIR		= 26,
	OP_READLINK		= 27,
	OP_REMOVE		= 28,
	OP_RENAME		= 29,
	OP_RENEW		= 30, /* Mandatory not-to-implement */
	OP_RESTOREFH		= 31,
	OP_SAVEFH		= 32,
	OP_SECINFO		= 33,
	OP_SETATTR		= 34,
	OP_SETCLIENTID		= 35, /* Mandatory not-to-implement */
	OP_SETCLIENTID_CONFIRM	= 36, /* Mandatory not-to-implement */
	OP_VERIFY		= 37,
	OP_WRITE		= 38,
	OP_RELEASE_LOCKOWNER	= 39, /* Mandatory not-to-implement */
	OP_BACKCHANNEL_CTL	= 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID		= 42,
	OP_CREATE_SESSION	= 43,
	OP_DESTROY_SESSION	= 44,
	OP_FREE_STATEID		= 45,
	OP_GET_DIR_DELEGATION	= 46,
	OP_GETDEVICEINFO	= 47,
	OP_GETDEVICELIST	= 48,
	OP_LAYOUTCOMMIT		= 49,
	OP_LAYOUTGET		= 50,
	OP_LAYOUTRETURN		= 51,
	OP_SECINFO_NO_NAME	= 52,
	OP_SEQUENCE		= 53,
	OP_SET_SSV		= 54,
	OP_TEST_STATEID		= 55,
	OP_WANT_DELEGATION	= 56,
	OP_ILLEGAL		= 10044
};

/* Set up Default result structure */

union resdata_t switch(ctrl_opnum ctrlop) {
 case CTRL_GRAB:   GRABres grab;
 default:
	 void;
 };

struct CTRLres {
	stat_t status;
	resdata_t data;
};

/*
 * 1 RESET - removes all previous server modifications
 *
 * void -> OK
 */

/*
 * 2 RECORD - starts recording of xdr traffic on server
 *
 * stamp is added to recorded data
 *
 * stamp -> OK
 */

struct RECORDarg {
	str stamp;
};

/*
 * 3 PAUSE - stop recording, leave op's queues alone
 *
 * void -> OK
 */

/*
 * 4 GRAB - return upto @number oldest records with specified @stamp
 *
 * op -> (OK, NOT_AVAIL), result
 */
struct GRABarg {
	int32_t number;
	dir_t   dir;
	str     stamp;
};

struct GRABres {
	str calls<>;
	str replies<>;
};

union CTRLarg switch(ctrl_opnum ctrlop) {
 case CTRL_RESET:  void;
 case CTRL_RECORD: RECORDarg record;
 case CTRL_PAUSE:  void;
 case CTRL_GRAB:   GRABarg   grab;
 };


