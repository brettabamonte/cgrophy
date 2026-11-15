/*
Extension module for cgrophy

Documentation used:
https://docs.python.org/3.14/extending/extending.html
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdlib.h>

extern PyTypeObject Sha1Type;
extern PyTypeObject Sha256Type;

/* - - - Module internals - - - */

static int cgrophy_hash_module_exec(PyObject *m) {
    if (PyType_Ready(&Sha1Type) < 0) {
      return -1;
    }

    if (PyType_Ready(&Sha256Type) < 0)
    {
        return -1;
    }

    if (PyModule_AddObjectRef(m, "Sha1", (PyObject *)&Sha1Type) < 0) {
      return -1;
    }
    if (PyModule_AddObjectRef(m, "Sha256", (PyObject *)&Sha256Type) < 0) {
      return -1;
    }

    return 0;
}

static PyModuleDef_Slot cgrophy_hash_module_slots[] = {
    {Py_mod_exec, cgrophy_hash_module_exec},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL}

};

static struct PyModuleDef cgrophy_hash_module = {.m_base = PyModuleDef_HEAD_INIT,
                                            .m_name = "_cgrophy_hash",
                                            .m_size = 0,
                                            .m_slots = cgrophy_hash_module_slots};

PyMODINIT_FUNC PyInit__cgrophy_hash(void) {
  return PyModuleDef_Init(&cgrophy_hash_module);
}
