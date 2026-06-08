"""Test repo with insecure configuration flags for each check_insecure_* tool."""
import hashlib
import random
import subprocess

import requests
from flask import Flask, make_response
from jinja2 import Environment

app = Flask(__name__, debug=True)  # CWE-489: debug=True


def set_session(value):
    resp = make_response("ok")
    # CWE-614: cookie without secure/httponly, samesite=None
    resp.set_cookie("session", value, secure=False, httponly=False, samesite="None")
    return resp


def fetch(url):
    # CWE-295: verify=False disables certificate validation
    return requests.get(url, verify=False)


def run_cmd(cmd):
    # CWE-78: shell=True enables command injection
    return subprocess.run(cmd, shell=True)


def render(tmpl):
    # CWE-79: autoescape=False allows XSS
    env = Environment(autoescape=False)
    return env.from_string(tmpl)


def hash_password(pw):
    # CWE-327: weak hash
    return hashlib.md5(pw.encode()).hexdigest()


def make_token():
    # CWE-330: non-crypto randomness for a token
    return str(random.randint(1000, 9999))


if __name__ == "__main__":
    app.run(debug=True)  # CWE-489 again
