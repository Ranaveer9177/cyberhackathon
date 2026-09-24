import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_db():
    return sqlite3.connect("fastnote.db")

@app.route("/api/notes/<note_id>", methods=["GET"])
def get_note(note_id):
    db = get_db()
    cursor = db.cursor()
    # Vulnerable: Python f-string SQL injection sink
    query = f"SELECT * FROM notes WHERE id = {note_id} AND is_private = 0"
    cursor.execute(query)
    return {"note": cursor.fetchone()}

@app.route("/api/users/search", methods=["GET"])
def search_users():
    db = get_db()
    cursor = db.cursor()
    term = request.args.get("q", "")
    # Vulnerable: String concatenation SQL injection sink
    sql = "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
    cursor.execute(sql)
    return {"results": cursor.fetchall()}
