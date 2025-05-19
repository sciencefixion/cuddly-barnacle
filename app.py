from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import boto3
import secrets
import base64
from botocore.exceptions import ClientError
import logging
from logging.handlers import RotatingFileHandler
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)

# ======================
# Configuration Settings
# ======================

def get_flask_secret():
    """Retrieve secret key from AWS Secrets Manager with fallback options"""
    secret_name = "prod/flask/app_secret"
    region_name = "us-east-2"

    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        
        if 'SecretBinary' in response:
            secret = base64.b64decode(response['SecretBinary'])
        else:
            secret = response['SecretString']
            
        return json.loads(secret)['flask_secret_key']
    except ClientError as e:
        app.logger.error(f"AWS Secrets Manager Error: {e.response['Error']['Code']}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error retrieving secret: {str(e)}")
        return None

# Set secret key with multiple fallback options
secret_key = (
    get_flask_secret() or 
    os.environ.get('FLASK_SECRET_KEY') or 
    secrets.token_hex(32)
)
app.secret_key = secret_key

if not get_flask_secret() and not os.environ.get('FLASK_SECRET_KEY'):
    app.logger.warning("Using temporary secret key - not suitable for production!")

app.config.update(
    # Security settings
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
    SESSION_COOKIE_NAME='flask_app_session',  # Explicit name
    SESSION_REFRESH_EACH_REQUEST=True,
    
    # Database settings
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_POOL_RECYCLE=3600,  # Recycle connections every hour
    SQLALCHEMY_POOL_TIMEOUT=30,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_size': 20,
        'max_overflow': 10,
        'connect_args': {
            'ssl': {'ca': '/etc/ssl/certs/rds-combined-ca-bundle.pem'}  # Common Linux location for RDS SSL certificate
        }
    }
)

# ======================
# Logging Configuration
# ======================

def configure_logging():
    """Configure production-grade logging"""
    root = logging.getLogger()
    if root.handlers:
        for handler in root.handlers:
            root.removeHandler(handler)

    if not os.path.exists('logs'):
        os.makedirs('logs')

    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application starting up')

configure_logging()

# ======================
# Database Configuration
# ======================

def get_db_secret(secret_name, region_name='us-east-2'):
    """Retrieve database credentials from AWS Secrets Manager"""
    try:
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except Exception as e:
        app.logger.error(f"Error fetching DB secret: {str(e)}")
        raise

try:
    secret = get_db_secret('prod/rds/mydb')
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{secret['username']}:{secret['password']}"
        f"@{secret['host']}/{secret['dbname']}?charset=utf8mb4"
    )
except Exception as e:
    app.logger.critical(f"Failed to configure database: {str(e)}")
    raise

db = SQLAlchemy(app)

# ======================
# AWS S3 Configuration
# ======================

BUCKET_NAME = 'flask-todo-april-bucket2'

def upload_file_to_s3(file_path, s3_key):
    """Upload file to S3 with proper error handling"""
    s3 = boto3.client("s3")
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

# ======================
# Database Models
# ======================

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
    s3_url = db.Column(db.String(500))

# ======================
# Authentication Setup
# ======================

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if not user:
        app.logger.error(f"User {user_id} not found!")
    return user

# ======================
# Application Routes
# ======================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        
        app.logger.info(f"New user registered: {username}")
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
            app.logger.info(f"User logged in: {username}")
            return redirect(url_for('home'))
        
        flash('Invalid username or password', 'error')
        app.logger.warning(f"Failed login attempt for: {username}")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    app.logger.info(f"Home accessed by: {current_user.id}")
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
@login_required
def add_task():
    task_title = request.form.get('task')
    file = request.files.get('file')

    if not task_title:
        flash('Task title is required', 'error')
        return redirect(url_for('home'))

    new_task = Task(title=task_title, user_id=current_user.id)

    if file and file.filename:
        try:
            if not os.path.exists('uploads'):
                os.makedirs('uploads')
                
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)
            s3_url = upload_file_to_s3(file_path, file.filename)
            new_task.s3_url = s3_url
            os.remove(file_path)
        except Exception as e:
            app.logger.error(f"File upload error: {str(e)}")
            flash('Error uploading file', 'error')

    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        app.logger.info(f"Task deleted: {task_id}")
    return redirect(url_for('home'))

@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        task.completed = True
        db.session.commit()
        app.logger.info(f"Task completed: {task_id}")
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
        app.logger.info(f"Task edited: {task_id}")
        return redirect(url_for('home'))
    
    return render_template('edit.html', task=task)

# ======================
# Application Startup
# ======================

if __name__ == '__main__':
    # Create required directories
    for directory in ['uploads', 'logs']:
        if not os.path.exists(directory):
            os.makedirs(directory)
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    # Run application
    app.run(host='0.0.0.0', port=5000, debug=True)