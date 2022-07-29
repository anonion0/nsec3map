#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/evp.h>

struct hash_ctx {
	int iterations;
	Py_ssize_t salt_length;
	const unsigned char *salt;
};

int compute_hash(const unsigned char *dn, unsigned int dn_length,
		struct hash_ctx *ctx, unsigned char *result,
		unsigned int *presult_len);

PyMODINIT_FUNC PyInit_nsec3hash(void);
static PyObject *py_compute_hash(PyObject *self, PyObject *args);

static PyMethodDef nsec3_methods[] = {
	{"compute_hash", py_compute_hash, METH_VARARGS,
		"compute an NSEC3 hash"},
	{NULL, NULL, 0, NULL}
};

static struct PyModuleDef nsec3hash_module = {
	PyModuleDef_HEAD_INIT,
	"nsec3hash",
	NULL,
	-1,
	nsec3_methods,
};

static PyObject *nsec3hash_error;

PyMODINIT_FUNC PyInit_nsec3hash(void)
{
	PyObject *m;
	m = PyModule_Create(&nsec3hash_module);
	if (m == NULL) {
		return NULL;
	}

	nsec3hash_error = PyErr_NewException("nsec3hash.error", NULL, NULL);
	Py_XINCREF(nsec3hash_error);
	if (PyModule_AddObject(m, "error", nsec3hash_error) < 0) {
		Py_XDECREF(nsec3hash_error);
		Py_CLEAR(nsec3hash_error);
		Py_DECREF(m);
		return NULL;
	}

	return m;
}

int compute_hash(const unsigned char *dn, unsigned int dn_length,
		struct hash_ctx *ctx, unsigned char *result,
		unsigned int *presult_len)
{
	int i = 0;
	int ret = -1;
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		goto allocerror;
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL))
		goto error;
	if (1 != EVP_DigestUpdate(mdctx, dn, dn_length))
		goto error;
	if (1 != EVP_DigestUpdate(mdctx, ctx->salt, ctx->salt_length))
		goto error;
	if (1 != EVP_DigestFinal_ex(mdctx, result, presult_len))
		goto error;

	while (i++ < ctx->iterations) {
		if (1 != EVP_DigestInit_ex2(mdctx, NULL, NULL))
			goto error;
		if (1 != EVP_DigestUpdate(mdctx, result, *presult_len))
			goto error;
		if (1 != EVP_DigestUpdate(mdctx, ctx->salt, ctx->salt_length))
			goto error;
		if (1 != EVP_DigestFinal_ex(mdctx, result, presult_len))
			goto error;
	}

	ret = 0;

error:
	EVP_MD_CTX_free(mdctx);
allocerror:
	return ret;

}

static PyObject *py_compute_hash(PyObject *self, PyObject *args)
{
	struct hash_ctx ctx;
	const unsigned char *dn;
	Py_ssize_t dn_length;
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int result_len;

	/* dn, salt, iterations, result */
	if (!PyArg_ParseTuple(args, "y#y#i", &dn,
				&dn_length,
				&ctx.salt,
				&ctx.salt_length,
				&ctx.iterations))
		return NULL;
	if (-1 == compute_hash(dn, dn_length, &ctx, result, &result_len)) {
		PyErr_SetString(nsec3hash_error, "compute_hash() failed");
		return NULL;
	}
	return Py_BuildValue("y#", result, result_len);
}
