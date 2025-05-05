from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__)) # Get the directory of the current file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)

@app.route('/')
def home():
    tasks = Task.query.all()
    return render_template('index.html', tasks = tasks)

@app.route('/add', methods= ['POST'])
def add_task():
    task = request.form.get('task')
    new_task = Task(title=task)
    db.session.add(new_task)
    db.session.commit()
    return redirect('/')

@app.route('/delete/<int:task_id>')
def delete_task(task_id):
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    return redirect('/')

@app.route('/complete/<int:task_id>')
def complete_task(task_id):
    task = Task.query.get(task_id)
    task.completed = True
    db.session.commit()
    return redirect('/')

@app.route('/uncompleted')
def show_uncompleted():
    uncompleted_tasks = Task.query.filter_by(completed=False).all()  
    return render_template('index.html', tasks=uncompleted_tasks)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)