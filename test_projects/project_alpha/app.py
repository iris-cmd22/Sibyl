from flask import Flask, request, render_template_string

from database import get_user
from files import read_note
from commands import ping_host
from serialize import load_prefs

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args.get("id")
    return get_user(uid)


@app.route("/note")
def note():
    name = request.args.get("name")
    content = read_note(name)
    return render_template_string("<h1>Note: " + name + "</h1><pre>" + content + "</pre>")


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return ping_host(host)


@app.route("/prefs", methods=["POST"])
def prefs():
    blob = request.form.get("data")
    return str(load_prefs(blob))


if __name__ == "__main__":
    app.run()
