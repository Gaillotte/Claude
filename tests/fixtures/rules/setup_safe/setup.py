import os
import subprocess
from setuptools import setup
from setuptools.command.build_ext import build_ext

# The version-file idiom: exec of a LOCAL file into a namespace. Two of the 36
# real setup.py files on this host do this, and the generic exec/eval rule
# failed both.
version = {}
with open(os.path.join("widget", "version.py")) as fp:
    exec(fp.read(), version)

# A literal command is not injectable. requests' own setup.py does this behind
# `if sys.argv[-1] == "publish"`, and ruamel.yaml runs `pip install .`.
if os.environ.get("PUBLISH"):
    os.system("twine upload dist/*")

# Asking git for a version string is ordinary.
rev = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()


class BuildExt(build_ext):
    def build_extensions(self):
        build_ext.build_extensions(self)


setup(name="widget", version=version["__version__"], cmdclass={"build_ext": BuildExt})
