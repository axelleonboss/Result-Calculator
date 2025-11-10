from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from auth_utils import hash_password, verify_password, generate_otp, otp_expiry

app = Flask(__name__)
conn = sqlite3.connect('database.db', check_same_thread=False)
c = conn.cursor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = hash_password(request.form['password'])
        try:
            c.execute("INSERT INTO users (full_name, email, password_hash, is_verified) VALUES (?, ?, ?, ?)",
                      (name, email, password, False))
            conn.commit()
            return "User created! Now go login."
        except:
            return "Email already exists."
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and verify_password(password, user[3]):
            # Generate OTP and save
            otp = generate_otp()
            expiry = otp_expiry()
            c.execute("INSERT INTO otps (user_id, code, expires_at) VALUES (?, ?, ?)", (user[0], otp, expiry))
            conn.commit()
            # Simulate sending OTP (print in console)
            print(f"OTP for {email}: {otp}")
            return f"OTP sent! Check console. Enter at /verify"
        return "Invalid email or password."
    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email = request.form['email']
        entered_otp = request.form['otp']
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        otp_record = c.execute("SELECT * FROM otps WHERE user_id=? ORDER BY id DESC", (user[0],)).fetchone()
        if otp_record and otp_record[2] == entered_otp:
            c.execute("UPDATE users SET is_verified=? WHERE id=?", (True, user[0]))
            conn.commit()
            return "OTP verified! You are logged in."
        return "Invalid OTP."
    return render_template('verify.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000)
