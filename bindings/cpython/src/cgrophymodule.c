/*
Extension module for cgrophy

Documentation used:
https://docs.python.org/3.14/extending/extending.html
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
#include <malloc.h>
#endif

#include "sha1.h"
#include <stdio.h.>

typedef struct {
    PyObject_HEAD
    Sha1Ctx *ctx;
} Sha1;

/* - - - Class API - - - */

static PyObject *Sha1_update(PyObject *op, PyObject *args) {
    PyObject *o;
    Sha1 *self;

    /* Verify argument type */
    o = &args[0];

    if (!PyBytes_Check(o))
    {
        PyErr_SetString(PyExc_ValueError, "update() expects a bytes-like object");
        return NULL;
    }

    self = (Sha1 *)op;

    /* interact with library */
    //TODO (brett): get weak ref to pybytes obj - - - PyBytes_AsString(o)
    //TODO (brett): Py_ssize_t wraps ssize_t which is a signed int. cgrophy expects len as size_t which is unsigned
    assert(PyBytes_Size(o) >= 0);
    sha1_update(self->ctx, (void *)PyBytes_AsString(o), PyBytes_Size(o));

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Sha1_digest(PyObject *op) {
    Sha1 *self;
    unsigned char digest[20];
    PyObject *res;

    self = (Sha1 *)op;

    /* finalize digest */
    sha1_final(self->ctx, digest);

    /* do we need to inc ref count here or does client do that. From examples it seems like
     * client is responsible for owning reference to the handle we return ? */
    //TODO( brett); PyBytes expects char * but the digest assumes unsigned char
    res = PyBytes_FromStringAndSize(digest, 20);
    return res;
}

/* - - - Class internals - - - */

static PyObject *Sha1_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    (void)(args);
    (void)(kwds);
    Sha1 *self;
    self = (Sha1 *)type->tp_alloc(type, 0);
    if (self != NULL) {
      self->ctx = sha1_new();
      if (self->ctx == NULL)
      {
          Py_DECREF(self);
          return NULL;
      }
    }
    sha1_init(self->ctx);

    return (PyObject *)self;
}

static void Sha1_dealloc(PyObject *op)
{
    Sha1 *self = (Sha1 *)op;
    sha1_destroy(self->ctx);
    Py_TYPE(self)->tp_free(self);
}

static PyMethodDef Sha1_methods[] = {
    { "update", _PyCFunction_CAST(Sha1_update), METH_O, "Expand message being hashed" },
    { "digest", Sha1_digest, METH_NOARGS, "Finalize hash and get digest of message" },
    {NULL} /* Sentinel */
};

static PyTypeObject Sha1Type = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0).tp_name = "cgrophy.Sha1",
    .tp_doc = PyDoc_STR("Sha1 object that creates sha1 digest."),
    .tp_basicsize = sizeof(Sha1),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Sha1_new,
    .tp_dealloc = Sha1_dealloc,
    .tp_methods = Sha1_methods
};

/* - - - Module internals - - - */

static int cgrophy_module_exec(PyObject *m) {
  if (PyType_Ready(&Sha1Type) < 0) {
    return -1;
  }

  if (PyModule_AddObjectRef(m, "Sha1", (PyObject *)&Sha1Type) < 0) {
    return -1;
  }

  return 0;
}

static PyModuleDef_Slot cgrophy_module_slots[] = {
    {Py_mod_exec, cgrophy_module_exec},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL}

};

static struct PyModuleDef cgrophy_module = {.m_base = PyModuleDef_HEAD_INIT,
                                            .m_name = "cgrophy",
                                            .m_size = 0,
                                            .m_slots = cgrophy_module_slots};

PyMODINIT_FUNC PyInit_cgrophy(void) {
  return PyModuleDef_Init(&cgrophy_module);
}
