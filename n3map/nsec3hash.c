#include <Python.h>
#include <openssl/sha.h>

struct hash_ctx {
	unsigned int iterations;
	unsigned int salt_length;
	const unsigned char *salt;
};


PyMODINIT_FUNC initnsec3hash(void);

static PyObject *py_compute_hash(PyObject *self, PyObject *args);

int compute_hash(const unsigned char *dn, unsigned int dn_length,
		struct hash_ctx *ctx, unsigned char *result);


static PyMethodDef nsec3_methods[] = {
	{"compute_hash", py_compute_hash, METH_VARARGS,
		"compute an NSEC3 hash"},
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initnsec3hash(void)
{
	(void) Py_InitModule("nsec3hash", nsec3_methods);
}

int compute_hash(const unsigned char *dn, unsigned int dn_length,
		struct hash_ctx *ctx, unsigned char *result)
{
	int i = 0;
	SHA_CTX sha_ctx;

	SHA1_Init(&sha_ctx);
	SHA1_Update(&sha_ctx, dn, dn_length);
	SHA1_Update(&sha_ctx, ctx->salt, ctx->salt_length);
	SHA1_Final(result, &sha_ctx);
	while (i++ < ctx->iterations) {
		SHA1_Init(&sha_ctx);
		SHA1_Update(&sha_ctx, result, 20);
		SHA1_Update(&sha_ctx, ctx->salt, ctx->salt_length);
		SHA1_Final(result, &sha_ctx);
	}

	return 0;
}

static PyObject *py_compute_hash(PyObject *self, PyObject *args)
{
	struct hash_ctx ctx;
	const unsigned char *dn;
	unsigned int dn_length;
	unsigned char result[20];

	/* dn, salt, iterations, result */
	if (!PyArg_ParseTuple(args, "s#s#i", &dn,
				&dn_length,
				&ctx.salt,
				&ctx.salt_length,
				&ctx.iterations))
		return NULL;
	compute_hash(dn, dn_length, &ctx, result);
	return Py_BuildValue("s#", result, 20);
}
