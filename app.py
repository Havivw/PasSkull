import os
import sys
import time
import pickle
import base64
from io import BytesIO

# import timeit
import pyqrcode
import onetimepass
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from flask_paginate import Pagination, get_page_args
from wtforms.validators import Required, Length, EqualTo
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask import Flask, render_template, redirect, url_for, flash, session, abort, flash, request, Response, send_file

from Main import *

import background_tasks

# create application instance
app = Flask(__name__)

app.config.from_object('config')

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
ALLOWED_EXTENSIONS = app.config['ALLOWED_EXTENSIONS']
# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)
TABLE = "PasSkull"
KEYSPACE = "passkullspace"
search_results_by_username = {}



def get_results(results, offset=0, per_page=100):
    return results[offset: offset + per_page]

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def remove_password(username):
    User.query.filter_by(username=username).delete()
    db.session.commit()

def change_password(username, password, adminb):
    admin = User.query.filter_by(username=username).first()
    admin.password = password
    admin.admin = adminb
    db.session.commit()

class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))
    admin = db.Column(db.Boolean())

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return f'otpauth://totp/PasSkull:{self.username}?secret={self.otp_secret}&issuer=PasSkull'

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class AddUserForm(FlaskForm):
    """Add User Form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required(), Length(8, 15)])
    password_again = PasswordField('Password again', validators=[Required(), EqualTo('password', message='Passwords must match')])
    admin = BooleanField('Admin')
    submit = SubmitField('Add')


class ChangePasswordForm(FlaskForm):
    """Change Password Form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Length(8, 15)])
    password_again = PasswordField('Password again', validators=[EqualTo('password', message='Passwords must match')])
    admin = BooleanField('Admin')
    Remove = BooleanField('Remove')
    submit = SubmitField('Change')

class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required(), Length(8, 15)])
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')


@app.errorhandler(404)
def error404(error):

    if current_user.is_authenticated:
        return render_template("404.html"), 404
    return redirect(url_for('login'))

@app.errorhandler(500)
def error500(error):
    number = 500
    msg1 = 'Oops! Server Error!'
    msg2 = 'Sorry We Have problem inside the Server.'
    return render_template("error_page.html", number=number, msg1=msg1, msg2=msg2), 500

@app.errorhandler(405)
def error405(error):
    number = 405
    msg1 = 'Oops! Method Not Allowed!'
    msg2 = 'WHAT THE HELL ARE YOU DOING?!'
    return render_template("error_page.html", number=number, msg1=msg1, msg2=msg2), 405

@app.errorhandler(403)
def error403(error):
    number = 403
    msg1 = 'Forbidden!'
    msg2 = 'Can\'t access? Good!'
    return render_template("error_page.html", number=number,msg1=msg1, msg2=msg2), 403

@app.errorhandler(401)
def error401(error):
    number = 401
    msg1 = 'Unauthorized!'
    msg2 = 'What about login?! try it maybe its magic...'
    return render_template("error_page.html", number=number,msg1=msg1, msg2=msg2), 401


@app.route('/')
def index():
    count_users = len(User.query.limit(10).all())
    return render_template('index.html', ucount=count_users)


@app.route('/adduser', methods=['GET', 'POST'])
def adduser():

    try:
        if User.query.filter_by(username=current_user.username, admin=True).first():
            admin = True
        else:
            admin = False
        login_state = True
    except:
        admin = False
        login_state = False
    if current_user.is_authenticated and admin or len(User.query.limit(10).all()) == 0:
        form = AddUserForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is not None:
                flash('Username already exists.')
                return redirect(url_for('register'))
            # add new user to the database
            user = User(username=form.username.data, password=form.password.data, admin=form.admin.data)
            db.session.add(user)
            db.session.commit()

            # redirect to the two-factor auth page, passing username in session
            session['username'] = user.username
            return redirect(url_for('two_factor_setup'))
        return render_template('adduser.html', form=form)
    if login_state == False:
        return redirect(url_for('login'))
    else:
        flash('Not Admin user. Please contact the administrative user.')
        return redirect(url_for('index'))

@app.route('/passwordchange', methods=['GET', 'POST'])
def passwordchange():

    try:
        if User.query.filter_by(username=current_user.username, admin=True).first():
            admin = True
        else:
            admin = False
        login_state = True
    except:
        admin = False
        login_state = False

    if current_user.is_authenticated and admin:
        form = ChangePasswordForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is None:
                flash('User Dose\'t exists.')
                return redirect(url_for('passwordchange'))
            # change new user to the database
            if not form.remove.data:
                change_password(username=form.username.data, password=form.password.data, adminb=form.admin.data)
            else:
                remove_user(username=form.username.data)
            flash('User Details Change Successfully.')
        return render_template('passwordchange.html', form=form)
    if login_state == False:
        return redirect(url_for('login'))
    else:
        flash('Not Admin user. Please contact the administrative user.')
        return redirect(url_for('index'))


@app.route('/twofactor')
def two_factor_setup(): #todo: first validation
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():

    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():

    """User login route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('login'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data) or \
                not user.verify_totp(form.token.data):
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        # flash('You are now logged in!')
        return redirect(url_for('search'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():

    """User logout route."""
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/random')
def random():
    if current_user.is_authenticated:
        while True:
            try:
                with open("/data/Passkull/Web_Data/Password_hour", "rb") as f:
                    username, password = pickle.load(f)
                    break
            except Exception as e:
                print("Password_hour file not exist, trying again in 5 second")
                time.sleep(5)
        return render_template('password_of_the_Day.html', username=username, password=password)

    return redirect(url_for('login'))


@app.route('/search', methods=['GET', 'POST'])
def search():
    if current_user.is_authenticated:
        try:
            key = session['key']
        except:
            key = None
        if request.method == 'POST' or request.args.get('page') or key or current_user.username in search_results_by_username.keys():
            print(key)
            if key and current_user.username in search_results_by_username.keys():
                search_results_by_username.pop(current_user.username)
            try:
                session['key'] = (request.form['key'].strip()).lower()
                session['value'] = request.form['value'].strip()
            except:
                pass
            page, per_page, offset = get_page_args(page_parameter='page',
                                                   per_page_parameter='per_page')
            per_page = 100
            if current_user.username in search_results_by_username.keys():
                results = search_results_by_username[current_user.username]
            else:
                initilize_export_file(username=current_user.username, hashsearch=False)
                results = search_in_database_regex(key=session['key'], value=session['value'], keyspace=KEYSPACE, table=TABLE, username=current_user.username)
            len_results = len(results)
            pagination_results = get_results(results=results, offset=offset, per_page=per_page)
            pagination = Pagination(page=page, per_page=per_page, total=len_results, css_framework='bootstrap4')
            return render_template('search.html', results=pagination_results, page=page, per_page=per_page, pagination=pagination)
        else:
            return render_template('search.html', results=[])
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if current_user.is_authenticated:
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('upload'))

            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('upload'))
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{current_user.username}_PassDump.txt')
                file.save(file_path)
                read_file_and_upload(file_name=file_path, delimiter=',', keyspace=KEYSPACE, table=TABLE)
                os.remove(file_path)
                return redirect(url_for('search'))
        return render_template('upload.html')
    return redirect(url_for('login'))

@app.route('/userslist', methods=['GET', 'POST'])
def userslist():
    if current_user.is_authenticated:
        session['key'] = None
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('userslist'))

            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('userslist'))

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{current_user.username}_PassDump_Search.txt')
                file.save(file_path)
                results = search_list_in_db(file_list=file_path, keyspace=KEYSPACE, table=TABLE, username=current_user.username, hashsearch=False, key='mail')
                search_results_by_username[current_user.username] = results
                os.remove(file_path)
                print('Done')
            return redirect(url_for('search'))
        return render_template('userslist.html')
    return redirect(url_for('login'))


@app.route('/hashlist', methods=['GET', 'POST'])
def hashlist():
    if current_user.is_authenticated:
        session['key'] = None
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('hashlist'))

            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('hashlist'))

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{current_user.username}_PassDump_Search.txt')
                file.save(file_path)
                results = search_list_in_db(file_list=file_path, keyspace=KEYSPACE, table=TABLE, username=current_user.username, hashsearch=True, key='hash')
                search_results_by_username[current_user.username] = results
                os.remove(file_path)
                print('Done')
            return redirect(url_for('search'))
        return render_template('hashlist.html')
    return redirect(url_for('login'))
# create database tables if they don't exist yet
db.create_all()

@app.route('/removerow')
def remove_row():

    if current_user.is_authenticated:
        delete_row(keyspace=KEYSPACE, table=TABLE, id=request.args.get('id'))
        return redirect(url_for('search'))
    return redirect(url_for('login'))

@app.route('/export')
def export():

    if current_user.is_authenticated:
        file_path = f"/tmp/{current_user.username}_export.csv"
        try:
            with open(file_path) as fp:
                csv = fp.read()
            os.remove(file_path)
            return Response(
                csv,
                mimetype="text/csv",
                headers={"Content-disposition":
                             "attachment; filename=Dump_Export.csv"})
        except:
            flash('There is not last Export file to Downalod.')
            return redirect(url_for('search'))
    return redirect(url_for('login'))


@app.route('/status')
def status():
    if current_user.is_authenticated:
        while True:
            try:
                with open("/data/Passkull/Web_Data/DB_status", "rb") as f:
                    results = pickle.load(f)
                    break
            except Exception as e:
                print("DB_status file not exist, trying again in 5 second")
                time.sleep(5)
        return render_template('count.html', results=results)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
