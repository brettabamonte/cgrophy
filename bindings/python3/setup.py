from setuptools import Extension, setup

ext = Extension(
    name="cgrophy",
    sources=["src/cgrophymodule.c"],
    include_dirs=["include/", "lib/"],
    library_dirs=["lib/", "include/"],
    libraries=["sha1"],
)

setup(ext_modules=[ext])
