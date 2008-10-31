%{

void print_OID(gss_OID_desc oid)
{
        static char hex[] = "0123456789ABCDEF";
        int i;
        char c, *str;

        printf("%i : ", oid.length);
        str = (char *) oid.elements;
        for (i=0; i<oid.length; i++) {
                c = str[i];
                printf("%c", hex[(c&0xf0)>>4]);
                printf("%c", hex[c&0x0f]);
        }
        printf("\n");
}

void print_mechs(gss_OID_set mechs)
{
        int i;

        printf("There are %i OIDs in the set:\n", mechs->count);
        for (i=0; i<mechs->count; i++) {
                print_OID(mechs->elements[i]);
        }
}


void throw_exception(OM_uint32 major, OM_uint32 minor)
{
	printf("Called throw_exception(%i, %i)\n", major, minor);
	PyErr_NoMemory(); // XXX Make sure this works
	return;
}

/*******************************************/

/* Structure mapping to INTERNAL NAME type from RFC 2743.
 * ->handle is the actual value returned from gss calls, which is freed
 * automatically during the destructor call.  The others are the reults
 * of gss_display_name applied to ->handle.
 */
typedef struct {
	gss_name_t handle;
	gss_buffer_desc name_buffer;
	gss_OID oid;
} Name;

void delete_Name(Name *self)
{
	OM_uint32 minor;

	if (!self)
		return;
	printf("Called delete_Name()\n");
	/* Ignore any errors */
	gss_release_buffer(&minor, &self->name_buffer);
	if (self->handle)
		gss_release_name(&minor, &self->handle);
	free(self);
}

/* We have the handle, now fill the name and oid */
int _Name_fill(Name *self)
{
	OM_uint32 major, minor;

	major = gss_display_name(&minor, self->handle, &self->name_buffer,
				 &self->oid);
	if (major) {
		throw_exception(major, minor);
		return -1;
	}
	return 0;
}

/* This is called when creation is initiated directly from python */
Name *new_Name(gss_buffer_t name, gss_OID type)
{
	Name *self;
	OM_uint32 major, minor;

	self = calloc(1, sizeof(Name));
	if (!self) {
		PyErr_NoMemory(); // XXX Make sure this works
		return NULL;
	}
	major = gss_import_name(&minor, name, type, &(self->handle));
	if (major) {
		throw_exception(major, minor);
		free(self);
		return NULL;
	}
	if (_Name_fill(self)) {
		delete_Name(self);
		return NULL;
	}
	return self;
}

#if 0
/* This is called from typemaps when other calls need to create a Name obj */
Name *_internal_new_Name(gss_name_t name)
{
	Name *self;

	self = malloc(sizeof(Name));
	if (!self) {
		PyErr_NoMemory(); // XXX Make sure this works
		return NULL;
	}
	self->handle = name;
	if (_Name_fill(self)) {
		delete_Name(self);
		return NULL;
	}
	return self;
}
#endif

gss_buffer_t Name_name_get(Name *self)
{
	return &self->name_buffer;
}

gss_OID *Name_oid_get(Name *self)
{
	return &self->oid;
}

/*******************************************/

/* TODO: Why do we have ot allocate anything here?  Can't we just
 * attach the methods to  gss_OID? */
typedef struct {
	gss_OID handle;
} OID;

OID *new_OID(gss_OID oid)
{
	OID *self;
	self = malloc(sizeof(*self));
	if (!self) {
		PyErr_NoMemory();
		return NULL;
	}
	self->handle = oid;
	return self;
}

void delete_OID(OID *self)
{
	free(self);
}

gss_OID *OID_handle_get(OID *self)
{
	return &self->handle;
}

PyObject *OID_name_get(OID *self)
{
	PyObject *out;
	out = PyString_FromStringAndSize((char *)self->handle->elements,
					 self->handle->length);
	if (!out) {
		PyErr_NoMemory();
		return NULL;
	}
	return out;
}

/*******************************************/

/* TODO: Make this behave more like a sequence */
typedef struct {
	gss_OID_set handle;
	OID *array;
} OIDset;

OIDset *new_OIDset(gss_OID_set set)
{
	OIDset *self;

	self = malloc(sizeof(*self));
	if (!self) {
		PyErr_NoMemory();
		return NULL;
	}

	self->handle = set;
	return self;
}

void delete_OIDset(OIDset *self)
{
	OM_uint32  minor;
	printf("Called %s()\n", __func__);
	if (self) {
		if (self->handle)
			gss_release_oid_set(&minor, &self->handle);
		free(self);
	}
}

gss_OID_set *OIDset_handle_get(OIDset *self)
{
	return &self->handle;
}

PyObject *OIDset_list_get(OIDset *self)
{
	PyObject *out, *tmp;
	int i;

	out = PyTuple_New(self->handle->count);
	if (out == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	for (i=0; i < self->handle->count; i++) {
		tmp = PyString_FromStringAndSize((char *) self->handle->elements[i].elements,
						 self->handle->elements[i].length);
		if (!tmp) {
			Py_DECREF(out);
			PyErr_NoMemory();
			return NULL;
		}
		PyTuple_SET_ITEM(out, i, tmp);
	}
	return out;
}

/*******************************************/

typedef struct {
	gss_cred_id_t handle;
	OIDset *mechs;
	OM_uint32 lifetime;
	gss_cred_usage_t usage;
	Name *name;
	PyObject *py_name;
	PyObject *py_mechs;
} Credential;


Credential *new_Credential(gss_cred_usage_t usage,
			   gss_name_t name, gss_OID_set mechs, 
			   OM_uint32 lifetime)
{
	Credential *self;
	OM_uint32 ignore, major = 0, minor;

	self = calloc(1, sizeof(Credential));
	if (!self) {
		PyErr_NoMemory();
		return NULL;
	}
	self->name = calloc(1, sizeof(Name));
	if (!self->name) {
		PyErr_NoMemory();
		goto fail;
	}
	self->mechs = calloc(1, sizeof(*self->mechs));
	if (!self->mechs) {
		PyErr_NoMemory();
		goto fail;
	}

	major = gss_acquire_cred(&minor, name, lifetime, mechs, usage,
				 &self->handle, &self->mechs->handle,
				 &self->lifetime);
	if (major)
		goto gss_fail;
	gss_release_oid_set(&ignore, &self->mechs->handle);
	self->mechs->handle = NULL;

	/* Grab all available gss state regarding cred */
	major = gss_inquire_cred(&minor, self->handle, &self->name->handle,
				 &self->lifetime, &self->usage,
				 &self->mechs->handle);
	if (major)
		goto gss_fail;

	/* Create python representation of mechs */
	self->py_mechs = SWIG_NewPointerObj(SWIG_as_voidptr(self->mechs),
					   SWIGTYPE_p_OIDset, SWIG_POINTER_OWN);
	if (!self->py_mechs)
		goto fail;

	/* Create python representation of name */
	if (_Name_fill(self->name))
		goto fail;
	self->py_name = SWIG_NewPointerObj(SWIG_as_voidptr(self->name),
					   SWIGTYPE_p_Name, SWIG_POINTER_OWN);
	if (!self->py_name)
		goto fail;

	return self;

 gss_fail:
	throw_exception(major, minor);
 fail:
	gss_release_cred(&ignore, &self->handle);
	delete_OIDset(self->mechs);
	delete_Name(self->name);
	free(self);
	return NULL;
}

void delete_Credential(Credential *self)
{
	OM_uint32  minor;
	Py_XDECREF(self->py_name);
	Py_XDECREF(self->py_mechs);
	gss_release_cred(&minor, &self->handle);
	printf("Finished delete_Credential\n");
	free(self);
}

PyObject *Credential_name_get(Credential *self)
{
	Py_INCREF(self->py_name);
	return self->py_name;
}

PyObject *Credential_mechs_get(Credential *self)
{
	Py_INCREF(self->py_mechs);
	return self->py_mechs;
}

/*******************************************/

typedef struct {
	gss_ctx_id_t handle;
	gss_OID mech;
	OM_uint32 flags;
	OM_uint32 lifetime;
	gss_name_t source_name;
	gss_name_t target_name;
	int open;
} Context;

Context *new_Context(void) 
{
	Context *self;

	self = calloc(1, sizeof(Context));
	if (!self) {
		PyErr_NoMemory();
		return NULL;
	}
	return self;
}

void delete_Context(Context *self) 
{
	OM_uint32 minor;
	printf("Calling delete_Context()\n");
	if (self->handle)
		gss_delete_sec_context(&minor, &self->handle, NULL);
	/* XXX STUB - delete names */
	free(self);
}

gss_buffer_t Context_init(Context *self, 
		  Name *target, gss_buffer_t token, Credential *cred,
		  gss_OID mech, OM_uint32 flags, OM_uint32 lifetime,
		  gss_channel_bindings_t bindings)
{
	OM_uint32 major, minor;
	gss_buffer_t out_token;

	out_token = malloc(sizeof(gss_buffer_desc));
	if (!out_token) {
		PyErr_NoMemory();
		return NULL;
	}
	printf("calling gss_init_sec_context()\n");
	major = gss_init_sec_context(&minor, cred ? cred->handle : NULL,
				     &self->handle, target->handle, mech, flags,
				     lifetime, bindings, token,
				     &self->mech, out_token,
				     &self->flags, &self->lifetime);
	if ((major != GSS_S_COMPLETE) && (major != GSS_S_CONTINUE_NEEDED)) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	printf("success\n");
	if (major == GSS_S_COMPLETE) {
		// XXX set target and source name
		self->open = 1;
	}
	return out_token;
}

gss_buffer_t Context_accept(Context *self,
		    gss_buffer_t token, Credential *cred,
		    gss_channel_bindings_t bindings)
{
	OM_uint32 major, minor;
	gss_buffer_t out_token;

	out_token = malloc(sizeof(gss_buffer_desc));
	if (!out_token) {
		PyErr_NoMemory();
		return NULL;
	}
	/* NOTE we are ignoring delegated_cred_handle */
	major = gss_accept_sec_context(&minor, &self->handle,
				       cred ? cred->handle : NULL,
				       token, bindings,
				       &self->source_name,
				       &self->mech, out_token, 
				       &self->flags, &self->lifetime, NULL);
	if ((major != GSS_S_COMPLETE) && (major != GSS_S_CONTINUE_NEEDED)) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	if (major == GSS_S_COMPLETE) {
		// XXX set target and source name
		self->open = 1;
	}
	return out_token;
}

gss_buffer_t Context_getMIC(Context *self,
			    gss_buffer_t msg, gss_qop_t qop)
{
	OM_uint32 major, minor;
	gss_buffer_t out_token;

	/* STUB - need to check self->open */
	out_token = malloc(sizeof(gss_buffer_desc));
	if (!out_token) {
		PyErr_NoMemory();
		return NULL;
	}
	major = gss_get_mic(&minor, self->handle, qop, msg, out_token);
	if (major) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	return out_token;
}

gss_qop_t Context_verifyMIC(Context *self, 
			    gss_buffer_t msg, gss_buffer_t token)
{
	OM_uint32 major, minor;
	gss_qop_t qop;

	/* STUB - need to check self->open */
	major = gss_verify_mic(&minor, self->handle, msg, token, &qop);
	if (major) {
		throw_exception(major, minor);
		return 0;
	}
	return qop;
}


gss_buffer_t Context_wrap(Context *self,
			  gss_buffer_t msg, gss_qop_t qop, int conf)
{
	OM_uint32 major, minor;
	gss_buffer_t out_token;
	int out_conf;

	/* STUB - need to check self->open */
	out_token = malloc(sizeof(gss_buffer_desc));
	if (!out_token) {
		PyErr_NoMemory();
		return NULL;
	}
	major = gss_wrap(&minor, self->handle, conf, qop, msg,
			 &out_conf, out_token);
	if (major) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	if (out_conf != conf) {
		printf("conf mismatch\n");
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	return out_token;
}

PyObject *Context_unwrap(Context *self, gss_buffer_t token)
{
	OM_uint32 major, minor;
	gss_buffer_t out_token;
	int out_conf;
	gss_qop_t qop;
	PyObject *out_tuple, *list[2];

	/* STUB - need to check self->open */
	out_token = malloc(sizeof(gss_buffer_desc));
	if (!out_token) {
		PyErr_NoMemory();
		return NULL;
	}
	major = gss_unwrap(&minor, self->handle, token, out_token,
			 &out_conf, &qop);
	if (major) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	/* Need to build tuple */
	out_tuple = PyTuple_New(2); /* STUB - ignoring out_conf */
	if (out_tuple == NULL) {
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	/* NOTE - should allocate out_token on heap, 
	 * since don't return it directly
	 */
	list[0] = PyString_FromStringAndSize((char *)out_token->value,
					     out_token->length);
	if (list[0] == NULL) {
		Py_DECREF(out_tuple);
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}
	list[1] = PyInt_FromLong((long) qop);
	if (list[1] == NULL) {
		Py_DECREF(list[0]);
		Py_DECREF(out_tuple);
		free(out_token);
		throw_exception(major, minor);
		return NULL;
	}

	free(out_token);
	PyTuple_SET_ITEM(out_tuple, 0, list[0]);
	PyTuple_SET_ITEM(out_tuple, 1, list[1]);
	return out_tuple;
}


%}

