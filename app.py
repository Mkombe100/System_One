from flask import Flask, render_template, request, redirect, session
import mysql.connector
import bcrypt

app = Flask(__name__)
app.secret_key = "secret"


# ---------- REGISTER ----------
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #store password in hash codes o any one cant know password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'),
        bcrypt.gensalt())

        # Connect to MySQL
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@Mkombe0966",
            database="simple_site"
        )
        cursor = conn.cursor()

        # Check if username exists
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            return "Username already exists!"

        # Insert user
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s,%s,'user')",
            (username, hashed_password.decode('utf-8'))
        )
        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template('index.html')


# ---------- LOGIN ----------
# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Connect to MySQL
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="@Mkombe0966",
            database="simple_site"
        )
        cursor = conn.cursor()
        # Note: comma is needed to make a single-element tuple
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user[2]
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect('/dashboard')
            else:
                return "Invalid username or password!"
        else: 
            return "Invalid username or password"

    return render_template('login.html')








# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        if session['role'] == 'admin':
            return render_template('admin.html', username=session['username'])
        else:
            return render_template('user.html', username=session['username'])
    return redirect('/login')


# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
