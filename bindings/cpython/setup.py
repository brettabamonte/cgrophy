from pathlib import Path
from setuptools import Extension, setup

try:
    import tomllib as toml
except ImportError:
    import tomli as toml

pyproject_toml = Path(__file__).parent / "pyproject.toml"
with open(pyproject_toml,"rb") as f:
    pyproject_data = toml.load(f)
project_data = pyproject_data["tool"]["cgrophy"]

includes = project_data["includes"]
libs = project_data["libs"]

ext = Extension(
    name="cgrophy",
    sources=["src/cgrophymodule.c"],
    include_dirs=includes,
    library_dirs=libs,
    libraries=["sha1"],
)

setup(
    ext_modules=[ext]
)
