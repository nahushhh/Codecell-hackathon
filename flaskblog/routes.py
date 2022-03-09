import email
from flask import render_template, url_for, flash, redirect, request
from flaskblog.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from flaskblog import app, db, bcrypt, mail
from flaskblog.models import User
from flask_login import login_user, current_user, logout_user
from flask_mail import Message

@app.route('/', methods=['GET', 'POST'])

@app.route("/home")
def home():
    return render_template('index.html', title='Home')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Your account has now been created. You can log in now!", 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)




@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def send_email(user):
    token = user.get_reset_token()
    message = Message('Password Reset Request', sender = 'patilnahush41@gmail.com', recipients = [user.email])
    message.body = f'''To reset your password follow the given link:
{url_for('reset_token',token=token, _external = True)}
This token is valid for 30 minutes.
If you did not make this request just ignore this email'''
    mail.send(message)

@app.route("/reset_password", methods=['GET', 'POST'])
def get_reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        send_email(user)
        flash("An email has been sent to reset your password",'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form = form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_token(token)
    if user is None:
        flash('Invalid or expired token','warning')
        return redirect(url_for('get_reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been updated.", 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title="Reset Password", form = form)
