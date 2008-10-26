%module gssapi
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

%typemap(python, in) gss_buffer_t INPUT (gss_buffer_desc temp) {
	printfred;
	if ($input == Py_None) {
		/* Allow None as equivalent to "" */
		$1 = NULL;
		//temp.value = NULL;
		//temp.length = 0;
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

#if 0
%typemap(python, in) gss_buffer_t INPUT (gss_buffer_desc temp) {
	printfred;
	if (SWIG_ConvertPtr($input, &temp, $*1_descriptor, SWIG_POINTER_EXCEPTION) == -1) {
		/* Assume is a python string */
		temp.value = (void *) PyString_AsString($input);
		if (!temp.value)
			return NULL;
		temp.length = strlen(temp.value) + 1;
	}
	$1 = ($1_ltype) &temp;
}
#endif

%typemap(python, in, numinputs=0) gss_buffer_t OUTPUT (gss_buffer_desc temp) {
	printfred;
	$1 = &temp;
}

%typemap(python, argout) gss_buffer_t OUTPUT {
	PyObject *o;
	printdict;
	o = PyString_FromStringAndSize($1->value, $1->length);
	if (!o)
		return NULL;
	if (PyDict_SetItemString($result, "$1_name", o) == -1)
		return NULL;
}

#if 0
%typemap(python, in, numinputs=0) gss_name_t *OUTPUT (gss_name_t temp) {
	printfred;
	$1 = &temp;
}
%typemap(python, argout) gss_name_t *OUTPUT {
	PyObject *o;
	printdict;
	o = PyString_FromStringAndSize(*($1), strlen(*($1)) + 1);
	//o = PyString_FromString(*($1));
	if (!o)
		return NULL;
	if (PyDict_SetItemString($result, "$1_name", o) == -1)
		return NULL;
}
%typemap(python, in) gss_name_t INPUT {
	printfred;
	$1 = PyString_AsString($input);
	if (!$1)
		return NULL;
}
#endif
	
%typemap(python, in, numinputs=0) void **OUTPUT (void *temp) {
	printfred;
	$1 = ($1_ltype) &temp;
}

%typemap(python, argout)  void **OUTPUT {
	/* returns a (void *) */
	printdict;
	if (PyDict_SetItemString($result, "$1_name", 
		       SWIG_NewPointerObj(*($1), $*1_descriptor, 0)) == -1)
		return NULL;
}

%typemap(python, in) void *INPUT {
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

%typemap(python, in) void **INOUT (void *temp) {
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

%typemap(python, default) void **INOUT (void *temp=NULL) {
	$1 = ($1_ltype) &temp; /* correctly set default to NULL */
}

#if 1
%typemap(python, argout) void **INOUT = void **OUTPUT;
#else
%typemap(python, argout) void **INOUT {
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
	
/*
 * All functions return OM_uint32, which corresponds to major.
 */
%typemap(python, out) OM_uint32 {
	/* Returns {"major":$1} */
	$result = PyDict_New();
	if (!$result ||
	    (PyDict_SetItemString($result, "major", PyInt_FromLong($1)) == -1))
		return NULL;
}

%typemap(python, in, numinputs=0) OM_uint32 *OUTPUT ($*1_type temp=0) {
	printfred;
	$1 = &temp;
}

%typemap(python, argout) OM_uint32 *OUTPUT {
	/* FRED - int *OUTPUT */
	printdict;
	if (PyDict_SetItemString($result, "$1_name", PyLong_FromUnsignedLong((unsigned long)*$1)) == -1)
		return NULL;
}

%apply OM_uint32 *OUTPUT {OM_uint32 *minor};

/***********************************/

/* Some helper code */
%inline {
char *ptr2str(void *ptr) {
	return (char *) ptr;
}
}
/***********************************/

/* Non-function declarations */

%rename (krb5oid) krb5oid_ptr;
%rename (HOSTBASED_SERVICE) GSS_C_NT_HOSTBASED_SERVICE;
%immutable;
extern gss_OID GSS_C_NT_HOSTBASED_SERVICE;
// extern gss_OID_desc krb5oid;
%inline {gss_OID krb5oid_ptr = &krb5oid;}
%mutable;
#define GSS_S_COMPLETE               0x00000000
#define GSS_S_CONTINUE_NEEDED        0x00000001

#define DELEG_FLAG 1
#define MUTUAL_FLAG 2
#define REPLAY_FLAG 4
#define SEQUENCE_FLAG 8
#define CONF_FLAG 16
#define INTEG_FLAG 32
#define	ANON_FLAG 64
#define PROT_READY_FLAG 128
#define TRANS_FLAG 256

typedef unsigned int OM_uint32;
typedef OM_uint32 gss_qop_t;
typedef void * gss_name_t;
typedef void * gss_cred_id_t;
typedef void * gss_ctx_id_t;
/***********************************/

/* Function declarations */


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
