from flask import Flask, request

app = Flask(__name__)


class DB:
    def queryDB(self, sql):  # custom wrapper the standard SQL query misses
        print("running", sql)


db = DB()


@app.route("/user")
def get_user():
    uid = request.args.get("id")          # remote source (user-controlled)
    sql = "SELECT * FROM users WHERE id = " + uid
    return db.queryDB(sql)                 # SQL injection sink (custom name)
