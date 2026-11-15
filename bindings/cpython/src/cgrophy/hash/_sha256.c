#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <malloc.h>
#endif

#include "sha256.h"

typedef struct {
    PyObject_HEAD
    Sha256Ctx *ctx;
} Sha256;

/* - - - Class API - - - */

static PyObject *Sha256_update(PyObject *op, PyObject *args) {
    PyObject *o;
    Sha256 *self;

    /* Verify argument type */
    o = &args[0];

    if (!PyBytes_Check(o))
    {
        PyErr_SetString(PyExc_ValueError, "update() expects a bytes-like object");
        return NULL;
    }

    self = (Sha256 *)op;

    /* interact with library */
    //TODO (brett): get weak ref to pybytes obj - - - PyBytes_AsString(o)
    //TODO (brett): Py_ssize_t wraps ssize_t which is a signed int. cgrophy expects len as size_t which is unsigned
    assert(PyBytes_Size(o) >= 0);
    sha256_update(self->ctx, (void *)PyBytes_AsString(o), PyBytes_Size(o));

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Sha256_digest(PyObject *op) {
    Sha256 *self;
    unsigned char digest[32];
    PyObject *res;

    self = (Sha256 *)op;

    /* finalize digest */
    sha256_final(self->ctx, digest);

    /* do we need to inc ref count here or does client do that. From examples it seems like
     * client is responsible for owning reference to the handle we return ? */
    //TODO( brett); PyBytes expects char * but the digest assumes unsigned char
    res = PyBytes_FromStringAndSize(digest, 32);
    return res;
}

/* - - - Class internals - - - */

static PyObject *Sha256_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    (void)(args);
    (void)(kwds);
    Sha256 *self;
    self = (Sha256 *)type->tp_alloc(type, 0);
    if (self != NULL) {
      self->ctx = sha256_new();
      if (self->ctx == NULL)
      {
          Py_DECREF(self);
          return NULL;
      }
    }
    sha256_init(self->ctx);

    return (PyObject *)self;
}

static void Sha256_dealloc(PyObject *op)
{
    Sha256 *self = (Sha256 *)op;
    sha256_destroy(self->ctx);
    Py_TYPE(self)->tp_free(self);
}

static PyMethodDef Sha256_methods[] = {
    { "update", _PyCFunction_CAST(Sha256_update), METH_O, "Expand message being hashed" },
    { "digest", Sha256_digest, METH_NOARGS, "Finalize hash and get digest of message" },
    {NULL} /* Sentinel */
};

PyTypeObject Sha256Type = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0).tp_name = "cgrophy.hash.Sha256",
    .tp_doc = PyDoc_STR("Sha256 object that creates sha256 digest."),
    .tp_basicsize = sizeof(Sha256),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Sha256_new,
    .tp_dealloc = Sha256_dealloc,
    .tp_methods = Sha256_methods
};
