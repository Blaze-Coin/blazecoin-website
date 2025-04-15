from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'blazecoin_secret_key'  # Change this to a strong secret in production

DATABASE = os.path.join("database", "users.db")

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return redirect(url_for('login'))

# Registration endpoint (GET and POST)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            return render_template("register.html", message="Please fill in all fields.")
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user:
            conn.close()
            return render_template("register.html", message="Username already exists.")
        password_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        conn.close()
        return redirect(url_for("login"))
    return render_template("register.html")

# Login endpoint (GET and POST)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return redirect(url_for("wallet"))
        else:
            return render_template("login.html", message="Invalid username or password.")
    return render_template("login.html")

# Wallet page - protected route
@app.route("/wallet")
def wallet():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("wallet.html", username=session["username"])

# API endpoint for miner authentication
@app.route("/auth_miner", methods=["POST"])
def auth_miner():
    # Expect JSON: { "username": "user", "password": "pass" }
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"status": "fail", "message": "Invalid request"}), 400
    username = data["username"]
    password = data["password"]
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user["password"], password):
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

if __name__ == "__main__":
    os.makedirs("database", exist_ok=True)
    init_db()
    app.run(debug=True)
    