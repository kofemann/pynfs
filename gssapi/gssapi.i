/* This is the name of the created module */
%module gssapi

/* This code is inserted directly into the created *_wrap.c file */
%{
#ifdef HEIMDAL 
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#if 0 /* I don't think these are needed */
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#endif
#endif /* HEIMDAL */

gss_OID_desc krb5oid = {
	.length = 9,
	.elements = "\052\206\110\206\367\022\001\002\002"};

%}

/* Debugging */
#if 0
#define printdict printf("Adding $1_name""\n")
#define printfred printf("FRED: $1_name""\n")
#else
#define printdict 
#define printfred 
#endif
/***********************************/


/* Typemaps */

/* Used for routines that take input directly from user, as opposed
 * to other gssapi routines.
 */
#ifdef SWIGPYTHON
/* typemap(in) type name (params):
 *     Convert Python->C anything that matches "type name" that is used
 *     as input to a function.  For output-only variables, where the
 *     inpute value is ignored, use 'numinputs=0'
 *     Variable: $input
 *
 * typemap(out) type name:
 *     Convert C->Python  the return value of functions
 *     Variable: $result
*/
%typemap(in) gss_buffer_t INPUT (gss_buffer_desc temp) {
	printfred;
	if ($input == Py_None) {
		/* None is different than "" */
		$1 = NULL;
		/* Allow None as equivalent to "" */
		//temp.value = NULL;
		//temp.length = 0;
		//$1 = &temp;
	}
	else {
		int stat;
		stat = PyString_AsStringAndSize($input, 
						(char **) &temp.value, 
						(int *) &temp.length);

		if (stat == -1)
			return NULL;
		//temp.length++; /* Add null to count*/
		$1 = &temp;
	}
}

%typemap(in, numinputs=0) gss_buffer_t OUTPUT (gss_buffer_desc temp) {
	printfred;
	$1 = &temp;
}

%typemap(argout) gss_buffer_t OUTPUT {
	PyObject *o;
	OM_uint32 major, minor;
	printdict;
	o = PyString_FromStringAndSize($1->value, $1->length);
	if (!o)
		return NULL;
	if (PyDict_SetItemString($result, "$1_name", o) == -1)
		return NULL;
	/* The returned buffer will never be reference again, since
	 * data has been copied to the Python string.
	 */
	major = gss_release_buffer(&minor, $1);
	if (major) {
		/* Better error handling needed */
		return NULL;
	}
}

%typemap(in, numinputs=0) void **OUTPUT (void *temp) {
	printfred;
	$1 = ($1_ltype) &temp;
}

%typemap(argout)  void **OUTPUT {
	/* returns a (void *) */
	printdict;
	if (PyDict_SetItemString($result, "$1_name", 
		       SWIG_NewPointerObj(*($1), $*1_descriptor, 0)) == -1)
		return NULL;
}

%typemap(in) void *INPUT {
	printfred;
	if (SWIG_ConvertPtr($input, &$1, $1_descriptor, SWIG_POINTER_EXCEPTION) == -1) {
		/* Assume is a python string */
		PyErr_Clear();
		$1 = (void *) PyString_AsString($input);
		if (!$1)
			return NULL;
		/* Convert '' to NULL */
		if (!*(char *)$1)
			$1 = NULL;
	}
}

%typemap(in) void **INOUT (void *temp) {
	/* $input is a (void *) */
	printfred;
	if (SWIG_ConvertPtr($input, &temp, $*1_descriptor, SWIG_POINTER_EXCEPTION) == -1) {
		/* Assume is a python string */
		PyErr_Clear();
		temp = (void *) PyString_AsString($input);
		if (!temp)
			return NULL;
		/* Convert '' to NULL */
		if (!*(char *)temp)
			temp = NULL;
	}
	$1 = ($1_ltype) &temp;
}

%typemap(default) void **INOUT (void *temp=NULL) {
	$1 = ($1_ltype) &temp; /* correctly set default to NULL */
}

#if 1
%typemap(argout) void **INOUT = void **OUTPUT;
#else
%typemap(argout) void **INOUT {
	PyObject *o;
	printdict;
	if (!*$1) {
		o = PyString_FromString("");
		//o = Py_None;
	}
	else {
		o = PyString_FromString((char *)*$1);
		if (!o)
			return NULL;
	}
	if (PyDict_SetItemString($result, "$1_name", o) == -1)
		return NULL;
}
	
#endif

%typemap(in, numinputs=0) OM_uint32 *OUTPUT ($*1_type temp=0) {
	printfred;
	$1 = &temp;
}

%typemap(argout) OM_uint32 *OUTPUT {
	/* FRED - int *OUTPUT */
	printdict;
	if (PyDict_SetItemString($result, "$1_name", PyLong_FromUnsignedLong((unsigned long)*$1)) == -1)
		return NULL;
}

%apply OM_uint32 *OUTPUT {OM_uint32 *minor};

#endif /* SWIGPYTHON */
/***********************************/

%include gssapi.c
%exception {
	PyObject *py_err;
	// ###ACTION###
	$action;
	// ###EXCEPTION### 
	py_err = PyErr_Occurred();
	if (py_err)
		return NULL;
}

%typemap(out) gss_buffer_t {
	PyObject *o;
	OM_uint32 minor;
	o = PyString_FromStringAndSize($1->value, $1->length);
	if (!o)
		return NULL;
	gss_release_buffer(&minor, $1);
	free($1);
	return o;
}

%typemap(out) gss_buffer_t const {
	PyObject *o;
	o = PyString_FromStringAndSize($1->value, $1->length);
	if (!o)
		return NULL;
	return o;
}

/* Try to make our own python classes */

/* Exports to user the readonly attributes handle, name, and oid.
 * name is the printable string user probably cares about.
 */
typedef struct {
	gss_name_t const handle;
	%extend {
		%apply gss_buffer_t INPUT {gss_buffer_t name};

		Name(gss_buffer_t name, gss_OID type);
		~Name();
		%clear gss_buffer_t name;
		gss_buffer_t const name;
		gss_OID * const oid;

	}
} Name;

typedef struct {
	%extend {
		OID(gss_OID oid);
		~OID();
		gss_OID * const handle;
		PyObject * const name;
	}
} OID;

typedef struct {
	%extend {
		OIDset(gss_OID_set set);
		~OIDset();
		gss_OID_set * const handle;
		PyObject * const list;
	}
} OIDset;

typedef struct {
	gss_cred_id_t const handle;
	OM_uint32 const lifetime;
	gss_cred_usage_t const usage;
	%extend {
		Credential(gss_cred_usage_t usage=GSS_C_INITIATE,
			   gss_name_t name=NULL, gss_OID_set mechs=NULL,
			   OM_uint32 lifetime=0);
		~Credential();
		PyObject * const mechs; /* Show as read-only tuple */
		PyObject * const name; /* Returns wrapped Name * */
	}
} Credential;

typedef struct {
	gss_ctx_id_t const handle;
	gss_OID const mech;
	OM_uint32 const flags;
	OM_uint32 const lifetime;
	gss_name_t const source_name;
	gss_name_t const target_name;
	int const open;
	%extend {
		Context();
		~Context();
		// typemap output token so it is immediately released
		// fix flags default
		%apply gss_buffer_t INPUT {gss_buffer_t token};
		%apply gss_buffer_t INPUT {gss_buffer_t msg};
		gss_buffer_t init(Name *target, gss_buffer_t token=NULL,
				  Credential *cred=NULL, gss_OID mech=NULL,
				  OM_uint32 flags=GSS_C_MUTUAL_FLAG,
				  OM_uint32 lifetime=0,
				  gss_channel_bindings_t bindings=NULL);
		gss_buffer_t accept(gss_buffer_t token,
				    Credential *cred=NULL,
				    gss_channel_bindings_t bindings=NULL);
		gss_buffer_t getMIC(gss_buffer_t msg, gss_qop_t qop=0);
		gss_qop_t verifyMIC(gss_buffer_t msg, gss_buffer_t token);
		gss_buffer_t wrap(gss_buffer_t msg, gss_qop_t qop=0,
				  int conf=1);
		PyObject *unwrap(gss_buffer_t token);
		%clear gss_buffer_t token;
		%clear gss_buffer_t msg;
	}
} Context;



/***********************************/

/* Some helper C code */
%inline {
char *ptr2str(void *ptr) {
	return (char *) ptr;
}
}

/***********************************/

/* Some helper python code */

%pythoncode %{
class _ReturnValue(object):
    """Used to convert a dict into class attributes"""
    def __init__(self, d):
        self.__dict__ = d

gss_major_codes = {
    0x00000000L : 'GSS_S_COMPLETE',
    0x00000001L : 'GSS_S_CONTINUE_NEEDED',
    0x00000002L : 'GSS_S_DUPLICATE_TOKEN',
    0x00000004L : 'GSS_S_OLD_TOKEN',
    0x00000008L : 'GSS_S_UNSEQ_TOKEN',
    0x00000010L : 'GSS_S_GAP_TOKEN',
    0x00010000L : 'GSS_S_BAD_MECH',
    0x00020000L : 'GSS_S_BAD_NAME',
    0x00030000L : 'GSS_S_BAD_NAMETYPE',
    0x00040000L : 'GSS_S_BAD_BINDINGS',
    0x00050000L : 'GSS_S_BAD_STATUS',
    0x00060000L : 'GSS_S_BAD_MIC',
    0x00060000L : 'GSS_S_BAD_SIG',
    0x00070000L : 'GSS_S_NO_CRED',
    0x00080000L : 'GSS_S_NO_CONTEXT',
    0x00090000L : 'GSS_S_DEFECTIVE_TOKEN',
    0x000a0000L : 'GSS_S_DEFECTIVE_CREDENTIAL',
    0x000b0000L : 'GSS_S_CREDENTIALS_EXPIRED',
    0x000c0000L : 'GSS_S_CONTEXT_EXPIRED',
    0x000d0000L : 'GSS_S_FAILURE',
    0x000e0000L : 'GSS_S_BAD_QOP',
    0x000f0000L : 'GSS_S_UNAUTHORIZED',
    0x00100000L : 'GSS_S_UNAVAILABLE',
    0x00110000L : 'GSS_S_DUPLICATE_ELEMENT',
    0x00120000L : 'GSS_S_NAME_NOT_MN',
    0x01000000L : 'GSS_S_CALL_INACCESSIBLE_READ',
    0x02000000L : 'GSS_S_CALL_INACCESSIBLE_WRITE',
    0x03000000L : 'GSS_S_CALL_BAD_STRUCTURE',
}

def show_major(m):
    """Return string corresponding to major code"""
    if m == 0:
        return gss_major_codes[0]
    call = m & 0xff000000L
    routine = m & 0xff0000
    supp = m & 0xffff
    out = []
    if call:
        out.append(gss_major_codes[call])
    if routine:
        out.append(gss_major_codes[routine])
    if supp:
        out.append(gss_major_codes[supp])
    return ' | '.join(out)

class Error(Exception):
    def __init__(self, major, minor):
        self.major = major
	self.minor = minor
	self.name = show_major(major)

    def __repr__(self):
	return "gssapi.Error(major=%s, minor=%i)" % (self.name, self.minor)
%}


/***********************************/

/* Non-function declarations */

/* the format is %rename (<python name>) <C name> */
%rename (krb5oid) krb5oid_ptr;
%rename (NT_HOSTBASED_SERVICE) GSS_C_NT_HOSTBASED_SERVICE;
%rename (NT_USER_NAME) GSS_C_NT_USER_NAME;
%immutable;
extern gss_OID GSS_C_NT_HOSTBASED_SERVICE;
extern gss_OID GSS_C_NT_USER_NAME;
// extern gss_OID_desc krb5oid;
%inline {gss_OID krb5oid_ptr = &krb5oid;}
%mutable;
#define GSS_S_COMPLETE               0x00000000
#define GSS_S_CONTINUE_NEEDED        0x00000001

/*
 * Flag bits for context-level services.
 */
#define DELEG_FLAG 1
#define MUTUAL_FLAG 2
#define REPLAY_FLAG 4
#define SEQUENCE_FLAG 8
#define CONF_FLAG 16
#define INTEG_FLAG 32
#define	ANON_FLAG 64
#define PROT_READY_FLAG 128
#define TRANS_FLAG 256

/*
 * Credential usage options
 */
#define BOTH 0
#define INITIATE 1
#define ACCEPT 2

typedef unsigned int OM_uint32;
typedef OM_uint32 gss_qop_t;
typedef OM_uint32 gss_cred_usage_t;
typedef struct gss_name_struct * gss_name_t;
typedef struct gss_cred_id_struct * gss_cred_id_t;
typedef struct gss_ctx_id_struct * gss_ctx_id_t;

//typedef struct gss_buffer_desc_struct *gss_buffer_t;

/***********************************/

/* Function declarations */

// NOTE this applies to all following function declarations
%pythonappend %{
  val = _ReturnValue(val)
  # STUB - raise error when major bad
  if val.major != GSS_S_COMPLETE and val.major != GSS_S_CONTINUE_NEEDED:
    raise Error(val.major, val.minor)
%}

/*
 * All functions return OM_uint32, which corresponds to major.
 */
%typemap(out) OM_uint32 {
	/* Returns {"major":$1} */
	$result = PyDict_New();
	if (!$result ||
	    (PyDict_SetItemString($result, "major", PyInt_FromLong($1)) == -1))
		return NULL;
}

/*********************************************/
%rename (importName) gss_import_name;
%apply void **OUTPUT {gss_name_t *name};
//%apply gss_name_t *OUTPUT {gss_name_t *name};
%apply gss_buffer_t INPUT {gss_buffer_t name};
%feature("autodoc", "importName(string name, gss_OID name_type=HOSTBASED_SERVICE) -> name");
OM_uint32 gss_import_name
           (OM_uint32 *minor,		/* minor_status OUT*/
            gss_buffer_t name,		/* input_name_buffer IN */
            gss_OID name_type=GSS_C_NT_HOSTBASED_SERVICE,			/* input_name_type IN */
            gss_name_t *name		/* output_name OUT */
           );
%clear gss_name_t *name;
%clear gss_buffer_t name;

/********/

%{
/* Reorder arguments so we can set defaults easily */
OM_uint32 reordered_init_sec_context
	        (OM_uint32 *minor,		/* minor_status */
		 gss_name_t name,		/* target_name IN*/
		 gss_ctx_id_t *context,		/* context_handle INOUT*/
		 gss_buffer_t input_token,	/* input_token IN */
		 gss_cred_id_t cred,		/* claimant_cred_handle IN*/
		 gss_OID mech,			/* mech_type IN */
		 OM_uint32 req_flags,		/* req_flags IN*/
		 OM_uint32 time_req,		/* time_req IN */
		 gss_channel_bindings_t chan,	/* input_chan_bindings IN*/
		 gss_OID *actual_mech_type,	/* actual_mech_type OUT*/
		 gss_buffer_t output_token,	/* output_token OUT*/
		 OM_uint32 *ret_flags,		/* ret_flags OUT*/
		 OM_uint32 *time_rec) 		/* time_rec OUT*/ {
	return gss_init_sec_context(minor, cred, context, name, mech,
				    req_flags, time_req, chan, input_token,
				    actual_mech_type, output_token,
				    ret_flags, time_rec);
}
 %}

%rename (initSecContext) reordered_init_sec_context;
//%apply gss_name_t INPUT {gss_name_t name};
%apply void **INOUT {gss_ctx_id_t *context};
%apply void **OUTPUT {gss_OID *mech};
%apply gss_buffer_t OUTPUT {gss_buffer_t token};
%apply OM_uint32 *OUTPUT {OM_uint32 *flags, OM_uint32 *time};
%feature("autodoc", "initSecContext(gss_name_t name, gss_ctx_id_t *context=None, string token=None, gss_cred_id_t cred=None, gss_OID mech=krb5oid, int flags=0, int time=0, gss_channel_bindings_t chan=None) -> context, mech, token, flags, time");
OM_uint32 reordered_init_sec_context
	        (OM_uint32 *minor,		/* minor_status */
		 gss_name_t name,			/* target_name IN*/
		 gss_ctx_id_t *context=NULL,		/* context_handle INOUT*/
		 gss_buffer_t INPUT=NULL,		/* input_token IN */
		 gss_cred_id_t cred=NULL,		/* claimant_cred_handle IN*/
		 gss_OID mech=&krb5oid,		/* mech_type IN */
		 OM_uint32 flags=MUTUAL_FLAG,		/* req_flags IN*/
		 OM_uint32 time=0,			/* time_req IN */
		 gss_channel_bindings_t chan=NULL,	/* input_chan_bindings IN*/
		 gss_OID *mech,		/* actual_mech_type OUT*/
		 gss_buffer_t token,		/* output_token OUT*/
		 OM_uint32 *flags,		/* ret_flags OUT*/
		 OM_uint32 *time 		/* time_rec OUT*/
		 );
//%clear gss_name_t name;
%clear gss_ctx_id_t *context;
%clear gss_OID *mech;
%clear gss_buffer_t token;
%clear OM_uint32 *flags, OM_uint32 *time;

/********/

%feature("autodoc", "1");

%{
OM_uint32 reordered_gss_accept_sec_context
(OM_uint32 *minor,		/* minor_status */
            gss_buffer_t in_token,		/* input_token_buffer IN*/
            gss_ctx_id_t *context,		/* context_handle INOUT */
            gss_cred_id_t in_cred,		/* acceptor_cred_handle IN*/
            gss_channel_bindings_t chan,	/* input_chan_bindings IN*/
            gss_name_t *name,		/* src_name OUT*/
            gss_OID *mech,		/* mech_type OUT*/
            gss_buffer_t token,		/* output_token */
            OM_uint32 *flags,		/* ret_flags OUT*/
            OM_uint32 *time,		/* time_rec OUT*/
            gss_cred_id_t *cred		/* delegated_cred_handle OUT*/
 ) {
	return gss_accept_sec_context(minor, context, in_cred, in_token, chan,
				      name, mech, token, flags, time, cred);
}
%}

%rename (acceptSecContext) reordered_gss_accept_sec_context;
%apply void **INOUT {gss_ctx_id_t *context};
%apply gss_buffer_t INPUT {gss_buffer_t in_token};
%apply void **OUTPUT {gss_name_t *name};
%apply void **OUTPUT {gss_OID *mech};
%apply gss_buffer_t OUTPUT {gss_buffer_t token};
%apply OM_uint32 *OUTPUT {OM_uint32 *flags, OM_uint32 *time};
%apply void **OUTPUT {gss_cred_id_t *cred};
OM_uint32 reordered_gss_accept_sec_context
(OM_uint32 *minor,		/* minor_status */
            gss_buffer_t in_token,		/* input_token_buffer IN*/
            gss_ctx_id_t *context=NULL,		/* context_handle INOUT */
            gss_cred_id_t in_cred=NULL,		/* acceptor_cred_handle IN*/
            gss_channel_bindings_t chan=NULL,	/* input_chan_bindings IN*/
            gss_name_t *name,		/* src_name OUT*/
            gss_OID *mech,		/* mech_type OUT*/
            gss_buffer_t token,		/* output_token */
            OM_uint32 *flags,		/* ret_flags OUT*/
            OM_uint32 *time,		/* time_rec OUT*/
            gss_cred_id_t *cred		/* delegated_cred_handle OUT*/
           );
%clear gss_ctx_id_t *context;
%clear gss_buffer_t in_token;
%clear gss_name_t *name;
%clear gss_OID *mech;
%clear gss_buffer_t token;
%clear OM_uint32 *flags, OM_uint32 *time;
%clear gss_cred_id_t *cred;


/********/

%rename (getMIC) reordered_gss_get_mic;
%{
OM_uint32 reordered_gss_get_mic
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t ctx,		/* context_handle IN */
	    gss_buffer_t msg,		/* message_buffer IN */
	    gss_qop_t qop,			/* qop_req IN */
	    gss_buffer_t token		/* message_token OUT*/
	   ) {
	return gss_get_mic(minor, ctx, qop, msg, token);
}
%}
%apply gss_buffer_t INPUT {gss_buffer_t msg};
%apply gss_buffer_t OUTPUT {gss_buffer_t token};
%feature("autodoc", "getMIC(gss_ctx_id_t context, string msg, int qop) -> string checksum");
OM_uint32 reordered_gss_get_mic
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t INPUT,		/* context_handle IN */
	    gss_buffer_t msg,		/* message_buffer IN */
	    gss_qop_t qop=0,			/* qop_req IN */
	    gss_buffer_t token		/* message_token OUT*/
 );
%clear gss_buffer_t token;
%clear gss_buffer_t msg;

/********/

%rename (verifyMIC) gss_verify_mic;
%apply OM_uint32 *OUTPUT {gss_qop_t *qop};
%feature("autodoc", "verifyMIC(gss_ctx_id_t context, string msg, string checksum) -> qop");
OM_uint32 gss_verify_mic
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t INPUT,		/* context_handle IN */
	    gss_buffer_t INPUT,		/* message_buffer IN */
	    gss_buffer_t INPUT,		/* message_token IN */
	    gss_qop_t *qop		/* qop_state OUT */
	   );
%clear gss_qop_t *qop;

/********/

%feature("autodoc", "0");

%rename (wrap) reordered_gss_wrap;
%{
OM_uint32 reordered_gss_wrap
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t ctx,		/* context_handle IN */
	    int conf_req,		/* conf_req_flag IN */
	    gss_buffer_t in_msg,	/* input_message_buffer IN*/
	    gss_qop_t qop,		/* qop_req IN=0*/
	    int *confidential,		/* conf_state OUT*/
	    gss_buffer_t msg		/* output_message_buffer OUT*/
 ) {
	return gss_wrap(minor, ctx, conf_req, qop, in_msg, confidential, msg);
}
%}
%apply gss_buffer_t INPUT {gss_buffer_t in_msg};
%apply int *OUTPUT {int *confidential};
%apply gss_buffer_t OUTPUT {gss_buffer_t msg};
OM_uint32 reordered_gss_wrap
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t INPUT,		/* context_handle IN */
	    int conf_req,		/* conf_req_flag IN */
	    gss_buffer_t in_msg,	/* input_message_buffer IN*/
	    gss_qop_t qop=0,		/* qop_req IN=0*/
	    int *confidential,		/* conf_state OUT*/
	    gss_buffer_t msg		/* output_message_buffer OUT*/
 );
%clear gss_buffer_t in_msg;
%clear int *confidential;
%clear gss_buffer_t msg;

/********/

%rename (unwrap) gss_unwrap;
%apply gss_buffer_t OUTPUT {gss_buffer_t msg};
%apply int *OUTPUT {int *confidential};
%apply OM_uint32 *OUTPUT {gss_qop_t *qop};
OM_uint32 gss_unwrap
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t INPUT,		/* context_handle IN*/
	    gss_buffer_t INPUT,		/* input_message_buffer IN*/
	    gss_buffer_t msg,		/* output_message_buffer OUT */
	    int *confidential,			/* conf_state OUT*/
	    gss_qop_t *qop		/* qop_state OUT */
	   );
%clear gss_buffer_t msg;
%clear int *confidential;
%clear gss_qop_t *qop;


/********/

%rename (inquireContext) gss_inquire_context;
%apply void **OUTPUT {gss_name_t *source, gss_name_t *target};
%apply OM_uint32 *OUTPUT {OM_uint32 *time, OM_uint32 *flags};
%apply void **OUTPUT {gss_OID *mech};
%apply OM_uint32 *OUTPUT {int *initiated, int *open};
OM_uint32 gss_inquire_context
(OM_uint32 *minor,		/* minor_status */
	    gss_ctx_id_t ctx,		/* context_handle */
	    gss_name_t *source,		/* src_name */
	    gss_name_t *target,		/* targ_name */
	    OM_uint32 *time,		/* lifetime_rec */
	    gss_OID *mech,		/* mech_type */
	    OM_uint32 *flags,		/* ctx_flags */
	    int *initiated,           	/* locally_initiated */
	    int *open			/* open */
	   );
%clear gss_name_t *source, gss_name_t *target;
%clear OM_uint32 *time, OM_uint32 *flags;
%clear gss_OID *mech;
%clear int *initiated, int *open;

/********/

%rename (displayName) gss_display_name;
%apply gss_buffer_t OUTPUT {gss_buffer_t name};
%apply void **OUTPUT {gss_OID *name_type};
OM_uint32 gss_display_name
(OM_uint32 *minor,		/* minor_status */
            gss_name_t name,			/* input_name */
            gss_buffer_t name,		/* output_name_buffer */
            gss_OID *name_type		/* output_name_type */
           );
%clear gss_buffer_t name;
%clear gss_OID *name_type;

/********/

%rename (exportName) gss_export_name;
%apply gss_buffer_t OUTPUT {gss_buffer_t name};
OM_uint32 gss_export_name
(OM_uint32  *minor,		/* minor_status */
		 const gss_name_t name ,	/* input_name */
		 gss_buffer_t name		/* exported_name */
	);
%clear gss_buffer_t name;

/********/


%rename (inquireCred) gss_inquire_cred;
%apply void **OUTPUT {gss_name_t *name};
%apply void **OUTPUT {gss_OID_set *mechs};
%apply OM_uint32 *OUTPUT {OM_uint32 *lifetime};
%apply gss_cred_usage_t *OUTPUT {gss_cred_usage_t *usage};
OM_uint32 gss_inquire_cred
(OM_uint32 *minor,		/* minor_status */
            gss_cred_id_t cred,		/* cred_handle */
            gss_name_t *name,		/* name */
            OM_uint32 *lifetime,		/* lifetime */
            gss_cred_usage_t *usage,	/* cred_usage */
            gss_OID_set *mechs		/* mechanisms */
           );
%clear gss_name_t *name;
%clear gss_OID_set *mechs;
%clear OM_uint32 *lifetime;
%clear gss_cred_usage_t *usage;

/********/
%rename (acquireCred) gss_acquire_cred;
%apply void **OUTPUT {gss_cred_id_t *cred};
%apply void **OUTPUT {gss_OID_set *mechs};
%apply OM_uint32 *OUTPUT {OM_uint32 *lifetime};
OM_uint32 gss_acquire_cred
(OM_uint32 *minor,		/* minor_status */
            gss_name_t name,			/* desired_name IN*/
            OM_uint32 lifetime,			/* time_req IN*/
            gss_OID_set mechs=NULL,		/* desired_mechs IN*/
            gss_cred_usage_t usage=0,		/* cred_usage IN*/
            gss_cred_id_t *cred,	/* output_cred_handle OUT*/
            gss_OID_set *mechs,		/* actual_mechs OUT*/
            OM_uint32 *lifetime		/* time_rec OUT*/
           );
%clear gss_OID_set *mechs;
%clear gss_cred_id_t *cred;
%clear OM_uint32 *lifetime;

/********/
%rename (oid2str) gss_oid_to_str;

%apply gss_buffer_t OUTPUT {gss_buffer_t str};
OM_uint32 gss_oid_to_str
(OM_uint32 *minor,		/* minor_status */
	    gss_OID oid,			/* oid */
	    gss_buffer_t str		/* oid_str */
	   );
%clear gss_buffer_t str;
