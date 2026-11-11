/*
Extension module for Cgrophy
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
#include <malloc.h>
#endif

#include "sha1.h"

typedef struct {
  PyObject_HEAD Sha1Ctx *ctx;
} Sha1;

static PyTypeObject Sha1Type = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0).tp_name = "cgrophy.Sha1",
    .tp_doc = PyDoc_STR("Sha1 object that creates sha1 digest."),
    .tp_basicsize = sizeof(Sha1),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew};

static void Sha1_dealloc(PyObject *op) {
  Sha1 *self = (Sha1 *)op;
  free(self->ctx);
  Py_TYPE(self)->tp_free(self);
}

static PyObject *Sha1_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  Sha1 *self;
  self = (Sha1 *)type->tp_alloc(type, 0);
  if (self != NULL) {
    self->ctx = (Sha1Ctx *)malloc(sizeof(Sha1Ctx *));
  }
  sha1_init(self->ctx);

  return (PyObject *)self;
}

static PyObject *Sha1_update(PyObject *op) {
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *Sha1_digest(PyObject *op) {
  Py_INCREF(Py_None);
  return Py_None;
}

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
