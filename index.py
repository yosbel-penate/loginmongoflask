from flask import Flask, render_template, request, redirect, url_for
from flask_mongoengine import MongoEngine, Document
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import Email, Length, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

DB_URI = "mongodb+srv://mongouser:My6Gmkc3Zno7SVQ7@cluster0.kfbtu.mongodb.net/Personal?retryWrites=true&w=majority"

app.config["MONGODB_HOST"] = DB_URI

db = MongoEngine(app)
app.config['SECRET_KEY'] = '8f42a73054b1749f8f58848be5e6502c'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Document):
        meta = {'collection': 'User'}
        name = db.StringField()
        email = db.StringField( max_length=30)
        password = db.StringField()
        is_active=db.BooleanField()
        authenticated=db.BooleanField()
        @property
        def is_authenticated(self):
            return self.authenticated

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

class RegForm(FlaskForm):
    email = StringField('email',  validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                hey = User(email=form.email.data,password=hashpass).save()
                login_user(hey)
                return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('dashboard'))
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.email)

@app.route('/logout', methods = ['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
