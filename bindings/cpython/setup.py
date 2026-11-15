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
    name="_cgrophy_hash",
    sources=["src/cgrophy/hash/_sha1.c", "src/cgrophy/hash/_sha256.c", "src/cgrophy/hash/_hashmodule.c"],
    include_dirs=includes,
    library_dirs=libs,
    libraries=["sha1", "sha256"],
)

setup(
    ext_modules=[ext]
)
