import sqlite3
import datetime
from flask import Flask, g, request, session, redirect, url_for, render_template, flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('lucy.db')
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()


# 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/')
def index():
    if 'username' in session:
        if session['admin']:
            return redirect(url_for('admin_dashboard'))
        else:
            conn = sqlite3.connect('lucy.db')
            cursor = conn.cursor()
            # username
            user = session['username']

            conn.close()
            return render_template('index.html', user=user)
    else:
        return render_template('index.html')


# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']

        errors = []

        # Check if username already exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username = ?',
                       (username,))
        if cursor.fetchone() is not None:
            errors.append('Username already exists')

        # Check if passwords match
        if password1 != password2:
            errors.append('Passwords do not match')

        # If there are errors, render the signup page with the errors
        if errors:
            return render_template('signup.html', errors=errors)

        # userid = last row id + 1 if last row id is not null
        cursor.execute('SELECT MAX(user_id) FROM users')
        user_id = cursor.fetchone()[0]
        if user_id is None:
            user_id = 1
        else:
            user_id += 1

        hashed_password = generate_password_hash(password1)
        is_admin = 0
        cursor.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)',
                       (user_id, username, hashed_password, email, is_admin))
        conn.commit()
        conn.close()

        session['username'] = username
        session['admin'] = False
        return redirect(url_for('index'))
    else:
        return render_template('signup.html')


# Change password
@app.route('/changepassword', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']

        conn = get_db()
        cursor = conn.cursor()

        # Check if username and email match a user in the database
        cursor.execute(
            'SELECT username FROM users WHERE username = ? AND email = ?',
            (username, email))
        result = cursor.fetchone()

        if result is None:
            flash('Invalid username or email', 'error')
            return redirect(url_for('change_password'))

        # Check if passwords match
        if password1 != password2:
            flash('Passwords do not match', 'error')
            return redirect(url_for('change_password'))

        # Hash the new password and update the user's password in the database
        hashed_password = generate_password_hash(password1)
        cursor.execute('UPDATE users SET password = ? WHERE username = ?',
                       (hashed_password, username))
        conn.commit()
        conn.close()

        flash('Password updated successfully', 'success')
        return redirect(url_for('login'))
    else:
        messages = get_flashed_messages(with_categories=True)
        return render_template('recovery.html', messages=messages)


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result is not None and check_password_hash(result['password'],
                                                      password):
            session['username'] = username
            session['admin'] = result['is_admin']
            return redirect(url_for('index'))
        else:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


# Logout
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

#admin
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' in session and session['admin']:
        conn = get_db()
        cursor = conn.cursor()

        # Get all users from the users table
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()

        conn.close()
        user = session['username']

        return render_template('admin.html', users=users, user=user)
    else:
        return redirect(url_for('login'))

# other pages
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/account')
def account():
    return render_template('account.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/products_details')
def products_details():
    return render_template('products_details.html')

@app.route('/search')
def search():
    return render_template('search_bar.html')

@app.route('/reviews')
def reviews():
    return render_template('reviews.html')
# run
if __name__ == '__main__':
    app.run(port=5000, debug=True)
