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


typedef struct {
	gss_name_t ptr;
	char *name;
	gss_OID oid;
} Name;

void throw_exception(OM_uint32 major, OM_uint32 minor)
{
	printf("Called throw_exception(%i, %i)\n", major, minor);
	PyErr_NoMemory(); // XXX Make sure this works
	return;
}

Name *new_Name(gss_buffer_t name, gss_OID type)
{
	Name *self;
	OM_uint32 major, minor;

	self = calloc(1, sizeof(Name));
	if (!self) {
		PyErr_NoMemory(); // XXX Make sure this works
		return NULL;
	}
	if (name == NULL) {
		printf("No name given\n");
		return self;
	}
	major = gss_import_name(&minor, name, type, &(self->ptr));
	printf("ptr = %p\n", self->ptr);
	if (major) {
		throw_exception(major, minor);
		free(self);
		return NULL;
	}
	return self;
}

Name *Name_create(gss_name_t name)
{
	Name *self;
	self = malloc(sizeof(Name));
	if (!self) {
		PyErr_NoMemory(); // XXX Make sure this works
		return NULL;
	}
	self->ptr = name;
	self->name = NULL;
	return self;
}

void delete_Name(Name *self)
{
	OM_uint32 minor;
	printf("Called delete_Name()\n");
	gss_release_name(&minor, &self->ptr); // ignore any errors
	free(self);
}

char *Name_name_get(Name *self)
{
	static char temp[] = "Default";
	return temp;
}

void Name_name_set(Name *self, char *data)
{
	throw_exception(0,0);
}

/*******************************************/

typedef struct {
	gss_cred_id_t handle;
	gss_OID_set mechs;
	//PyObject *mechs; /* list */
	OM_uint32 lifetime;
	gss_cred_usage_t usage;
	gss_name_t name;
} Credential;


Credential *new_Credential(gss_cred_usage_t usage,
			   gss_name_t name, gss_OID_set mechs, 
			   OM_uint32 lifetime)
{
	Credential *self;
	OM_uint32 major, minor;

	self = calloc(1, sizeof(Credential));
	if (!self) {
		PyErr_NoMemory(); // XXX Make sure this works
		return NULL;
	}
	printf("Calling acquire_cred\n");
	major = gss_acquire_cred(&minor, name, lifetime, mechs, usage,
				 &self->handle, &self->mechs, &self->lifetime);
	printf("lifetime=%i\n", self->lifetime);
	if (major)
		goto fail;
	if (name != NULL) {
		/* Make sure we own a reference to self->name */
		major = gss_duplicate_name(&minor, name, &self->name);
		if (major)
			goto fail;
		self->usage = usage;
	}
	else {
		printf("calling inquire_cred\n");
		major = gss_inquire_cred(&minor, self->handle, &self->name,
					 &self->lifetime, &self->usage,
					 &self->mechs);
		if (major)
			goto fail;
	}
	return self;
 fail:
	throw_exception(major, minor);
	free(self);
	return NULL;
}

void delete_Credential(Credential *self)
{
	OM_uint32  minor;
	printf("Called delete_Credential()\n");
	gss_release_name(&minor, &self->name);
	gss_release_cred(&minor, &self->handle);
	gss_release_oid_set(&minor, &self->mechs);
	free(self);
}

PyObject *Credential_mechs_get(Credential *self)
{
	/* Convert oid_set into a python tuple */
	PyObject *out, **list;
	int i;

	list = calloc(self->mechs->count, sizeof(PyObject *));
	if (list == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	out = PyTuple_New(self->mechs->count);
	if (out == NULL) {
		free(list);
		PyErr_NoMemory();
		return NULL;
	}
	for (i=0; i < self->mechs->count; i++) {
		list[i] = PyString_FromStringAndSize((char *) self->mechs->elements[i].elements,
						  self->mechs->elements[i].length);
		if (list[i] == NULL) {
			int j;
			for (j=0; j<i; j++) {
				Py_DECREF(list[j]);
			}
			Py_DECREF(out);
			PyErr_NoMemory();
			free(list);
			return NULL;
		}
		PyTuple_SET_ITEM(out, i, list[i]);
	}
	return out;
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
				     &self->handle, target->ptr, mech, flags,
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

