from flask import Flask, request, jsonify, session, render_template, redirect, flash
from flask_cors import CORS
import mysql.connector
from datetime import datetime, date
import bcrypt

app = Flask(__name__)
app.secret_key = 'hostel_management_secret_key'
CORS(app)

# ----------------- Database -----------------
db_config = {
    'host': 'localhost',
    'user': 'ProjectUser',
    'password': 'ProjectPassword',  # CHANGE THIS
    'database': 'Hostel_Management_System'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

# ----------------- Password Utils -----------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_password: str, user_password: str) -> bool:
    try:
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# ----------------- Ensure Room Applications Table -----------------
def ensure_room_applications_table():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS room_applications (
                application_id INT PRIMARY KEY AUTO_INCREMENT,
                student_id INT NOT NULL,
                preferred_block VARCHAR(20),
                status ENUM('Pending','Approved','Rejected') DEFAULT 'Pending',
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        cur.close()
        conn.close()

ensure_room_applications_table()

# ----------------- Routes -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    # Handle form data or JSON
    if request.is_json:
        data = request.json
    else:
        data = request.form

    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    admission_date = data.get('admission_date') or date.today().isoformat()
    password = data.get('password')

    if not (name and email and password):
        flash('Missing required fields', 'error')
        return redirect('/register_page')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        # Check if email already exists
        cur.execute("SELECT * FROM students WHERE email=%s", (email,))
        if cur.fetchone():
            flash('Email already registered', 'error')
            return redirect('/register_page')

        # Insert student
        hashed_pw = hash_password(password)
        cur.execute(
            "INSERT INTO students (name, email, phone, admission_date, active, Password) "
            "VALUES (%s,%s,%s,%s,1,%s)",
            (name, email, phone, admission_date, hashed_pw)
        )
        conn.commit()
        student_id = cur.lastrowid

        # Optional: insert into users table for unified login
        cur.execute(
            "INSERT INTO users (username, password, role, linked_id) VALUES (%s,%s,'Student',%s)",
            (email, hashed_pw, student_id)
        )
        conn.commit()

        flash('Registration successful. Please login.', 'success')
        return redirect('/login')
    finally:
        cur.close()
        conn.close()

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if not (email and password and role):
            flash('Provide email, password, and role', 'error')
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        try:
            if role == 'student':
                cur.execute("SELECT * FROM users WHERE username=%s AND role='Student'", (email,))
                user = cur.fetchone()
                if user and check_password(user['password'], password):
                    cur.execute("SELECT * FROM students WHERE student_id=%s", (user['linked_id'],))
                    st = cur.fetchone()
                    session['user_id'] = st['student_id']
                    session['role'] = 'student'
                    session['name'] = st['name']
                    return redirect('/student_home')

            elif role == 'admin':
                if email == 'admin@hostel.com' and password == 'admin123':
                    session['user_id'] = 0
                    session['role'] = 'admin'
                    session['name'] = 'Admin'
                    return redirect('/admin_home')

            elif role == 'warden':
                cur.execute("SELECT * FROM users WHERE username=%s AND role='Warden'", (email,))
                warden = cur.fetchone()
                if warden:
                    session['user_id'] = warden['linked_id']
                    session['role'] = 'warden'
                    session['name'] = email
                    return redirect('/warden_home')

            flash('Invalid credentials', 'error')
            return redirect('/login')
        finally:
            cur.close()
            conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ----------------- Student Dashboard -----------------
@app.route('/student_home')
def student_home():
    if session.get('role') != 'student':
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT s.*, r.room_no, r.capacity, r.status AS room_status
            FROM students s LEFT JOIN rooms r ON s.room_id = r.room_id
            WHERE s.student_id=%s
        """, (session['user_id'],))
        student = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    return render_template('student_home.html', student=student)

# ----------------- Admin Dashboard -----------------
@app.route('/admin_home')
def admin_home():
    if session.get('role') != 'admin':
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT s.*, r.room_no FROM students s LEFT JOIN rooms r ON s.room_id=r.room_id")
        students = cur.fetchall()
        cur.execute("SELECT * FROM rooms")
        rooms = cur.fetchall()
        cur.execute("SELECT c.*, s.name AS student_name FROM complaints c JOIN students s ON c.student_id=s.student_id")
        complaints = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('admin_home.html', students=students, rooms=rooms, complaints=complaints)

# ----------------- Warden Dashboard -----------------
@app.route('/warden_home')
def warden_home():
    if session.get('role') != 'warden':
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT c.*, s.name AS student_name FROM complaints c JOIN students s ON c.student_id=s.student_id")
        complaints = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('warden_home.html', complaints=complaints)

# ----------------- Error Handler -----------------
@app.errorhandler(500)
def internal_error(e):
    return "Internal Server Error: " + str(e), 500

# ----------------- Run App -----------------
if __name__ == '__main__':
    app.run(debug=True, port=5000)
