from flask import Flask

from hashing import hash_password
from tokens import generate_token
from client import fetch

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret123"


@app.route("/login")
def login():
    token = generate_token()
    return token


@app.route("/mirror")
def mirror():
    return fetch("https://example.com/data")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
