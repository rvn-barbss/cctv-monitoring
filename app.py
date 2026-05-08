import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_exam_key' # You can change this if you want

# --- 1. Set up Intrusion Logging ---
# This creates the security.log file to catch your professor's attempts
logging.basicConfig(filename='security.log', level=logging.WARNING, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- 2. Set up Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mock Database for the Admin user
users = {
    "admin": generate_password_hash("password123") # Change "password123" to your actual secure password
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# --- 3. The Login Route ---
@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_ip = request.remote_addr

        if username in users and check_password_hash(users.get(username), password):
            user = User(username)
            login_user(user)
            logging.info(f"SUCCESSFUL LOGIN from IP: {client_ip}")
            return redirect(url_for('dashboard'))
        else:
            # THIS IS THE HONEYPOT LOG: Catching the failed attempts
            logging.warning(f"INTRUSION ALERT: Failed login attempt from IP: {client_ip} using username: {username}")
            flash('Invalid credentials')
    
    return render_template('login.html')

# --- 4. The Protected Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    # Only authenticated users can see this page
    return render_template('camera.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '_main_':
    # Bind to 0.0.0.0 so the whole network can access the site
    app.run(host='0.0.0.0', port=5000, debug=True)