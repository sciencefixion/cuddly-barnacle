from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import boto3
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)

# ========== Configuration Settings ==========
app.config.update(
    SECRET_KEY=os.eviron.get('FLASK_SECRET_KEY', os.random(24)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400, # 1 day in seconds
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_POOL_RECYCLE=3600, Recycle connections every hour
    SQLALCHEMY_POOL_TIMEOUT=30,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True, # Enable connection health checks
        'pool_recycle': 3600,
        'pool_size': 20,
        max_overflow: 10
    }
)

# ========== Enhanced Logging Setup ==========

def configure_logging():
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')

    #Production logging - rotates when reaches 10MB, keeps 5 backups
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1024*1024*10,
        backupCount=5,
        
    )
    file.handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

configure_logging()

# ========== Database Configuration ==========

def get_db_secret(secret_name, region_name='us-east-2'):
    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = get_secret_value_response['SecretString']
        return json.loads(secret)
    except Exception as e:
        app.logger.error(f"Error fetching DB secret: {str(e)}")
        raise

# Fetch credentials from Secrets Manager
try:
    secret = get_db_secret('prod/rds/mydb')
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{secret['username']}:{secret['password']}"
        f"@{secret['host']}/{secret['dbname']}?charset=utf8mb4"
    )
except Exception as e:
    app.logger.error(f"Failed to configure database: {str(e)}")
    raise

db = SQLAlchemy(app)

# ========== AWS S3 Configuration ==========
BUCKET_NAME = 'flask-todo-april-bucket2'

def upload_file_to_s3(file_path, s3_key):
    s3 = boto3.client("s3")
    file_name = os.path.basename(file_path)
    try:
        s3.upload_file(
            file_path, 
            BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ACL': 'private',
                'ContentType': 'application/octet-stream'
            }
        )
        app.logger.info(f"Uploaded {s3_key} to {BUCKET_NAME}")
        return f"https://{BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
    except Exception as e:
        app.logger.error(f"Error uploading file {s3_key}: {str(e)}")
        raise

# ============ Models =============

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    s3_url = db.Column(db.String(500)) #added for file storage

# ========== Flask-Login Configuration ==========

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong" # Enhanced session protection

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =========== Application Routes ==========

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('home'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Task Routes
@app.route('/')
@login_required
def home():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    task = request.form.get('task')
    try:
        file = request.files.get('file')
    except Exception as e:
        logging.error("Error retrieving file: %s", e)
        file = None

    new_task = Task(title=task, user_id=current_user.id)
    if file:
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)
        s3_url = upload_file_to_s3(file_path, BUCKET_NAME)
        os.remove(file_path)
        new_task.s3_url = s3_url
    else:
        logging.info("No file uploaded")
    if task:
        new_task = Task(title=task, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:  # Authorization check
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        task.completed = True
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        task.title = request.form['task']
        db.session.commit()
        return redirect(url_for('home'))
    
    return render_template('edit.html', task=task)

# ========== Application Startup ==========

if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    # Initialize database
    with app.app_context():
        db.create_all()

    # Run the application
    app.run(host='0.0.0.0', debug=True)