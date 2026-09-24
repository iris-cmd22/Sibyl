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
    
    resp.set_cookie("session", value, secure=False, httponly=False, samesite="None")
    return resp


def fetch(url):
   
    return requests.get(url, verify=False)


def run_cmd(cmd):
    return subprocess.run(cmd, shell=True)


def render(tmpl):
   
    env = Environment(autoescape=False)
    return env.from_string(tmpl)


def hash_password(pw):
   
    return hashlib.md5(pw.encode()).hexdigest()


def make_token():
    
    return str(random.randint(1000, 9999))


if __name__ == "__main__":
    app.run(debug=True)  # CWE-489 again
