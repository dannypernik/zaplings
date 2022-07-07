import os
from flask import Flask, render_template, flash, Markup, redirect, url_for, \
    request, send_from_directory, send_file
from app import app, db, login, hcaptcha
from app.forms import SignupForm, LoginForm, IntroForm, InquiryForm, IdeaForm, \
    LovesForm, OffersForm, NeedsForm, UserForm, RequestPasswordResetForm, ResetPasswordForm
from flask_login import current_user, login_user, logout_user, login_required, login_url
from app.models import User, Idea
from werkzeug.urls import url_parse
from datetime import datetime
from app.email import send_contact_email, send_password_email, \
    send_test_strategies_email, send_score_analysis_email, send_practice_test_email
from functools import wraps

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_viewed = datetime.utcnow()
        db.session.commit()

def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f))
                   for root_path, dirs, files in os.walk(folder)
                   for f in files))

def admin_required(f):
    @login_required
    @wraps(f)
    def wrap(*args, **kwargs):
        if current_user.is_admin:
            return f(*args, **kwargs)
        else:
            flash('You must have administrator privileges to access this page.', 'error')
            logout_user()
            return redirect(login_url('login', next_url=request.url))
    return wrap


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = IntroForm()
    if current_user.is_authenticated:
        return redirect(url_for('home', id=current_user.get_id()))
    if form.validate_on_submit():
        username_check = User.query.filter_by(username=form.email.data).first()
        if username_check is not None:
            if username_check.password_hash is None:
                send_password_email(username_check)
                flash('You need to verify your email before saving more ideas. Please check your inbox.', 'error')
                return redirect(url_for('login', email=form.email.data))
            flash('An account already exists for ' + form.email.data + '. Please log in.', 'error')
            return redirect(url_for('login', email=form.email.data, idea=form.description.data))
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
            email=form.email.data, username=form.email.data)
        db.session.add(user)
        db.session.flush()
        idea = Idea(description=form.description.data, creator_id=user.id)
        db.session.add(idea)
        db.session.commit()
        send_password_email(user)
        flash('Welcome to Zaplings! Please check your inbox at ' + user.email + ' to finish setting up your account.')
        return redirect(url_for('idea', id=idea.id))
    return render_template('index.html', form=form, last_updated=dir_last_updated('app/static'))

@app.route('/contact')
def contact():
    form = InquiryForm()
    if form.validate_on_submit():
        if hcaptcha.verify():
            pass
        else:
            flash('Please verify that you are human.', 'error')
            return render_template('index.html', form=form, last_updated=dir_last_updated('app/static'))
        user = User(first_name=form.first_name.data, email=form.email.data, phone=form.phone.data)
        message = form.message.data
        subject = form.subject.data
        send_contact_email(user, message, subject)
        flash('Please check ' + user.email + ' for a confirmation email. Thank you for reaching out!')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

@app.route('/about')
def about():
    return render_template('about.html', title="About")


@app.route('/home')
@login_required
def home():
    ideas = Idea.query.filter_by(creator_id=current_user.get_id())
    return render_template('home.html', title="Home", ideas=ideas)


@app.route('/idea/<int:id>', methods=['GET', 'POST'])
@login_required
def idea(id):
    form = IdeaForm()
    idea = Idea.query.get_or_404(id)
    if form.validate_on_submit():
        idea.name = form.name.data
        idea.tagline = form.tagline.data
        idea.description = form.description.data
        try:
            db.session.add(idea)
            db.session.commit()
            flash(idea.name + ' updated')
            return redirect(url_for('home'))
        except:
            db.session.rollback()
            flash(idea.name + ' could not be updated', 'error')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.name.data = idea.name
        form.tagline.data = idea.tagline
        form.description.data = idea.description
    return render_template('idea.html', form=form)


@app.route('/loves', methods=['GET', 'POST'])
@login_required
def loves():
    form = LovesForm()
    if form.validate_on_submit():
        current_user.loves = form.loves.data
    elif request.method == 'GET':
        form.loves.data = current_user.loves
    return render_template('loves.html', form=form)


@app.route('/offers', methods=['GET', 'POST'])
@login_required
def offers():
    form = OffersForm()
    if form.validate_on_submit():
        current_user.offers = form.offers.data
    elif request.method == 'GET':
        form.offers.data = current_user.offers
    return render_template('offers.html', form=form)


@app.route('/needs', methods=['GET', 'POST'])
@login_required
def needs():
    form = NeedsForm()
    if form.validate_on_submit():
        current_user.needs = form.needs.data
    elif request.method == 'GET':
        form.needs.data = current_user.needs
    return render_template('needs.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        flash('You are already signed in')
        return redirect(url_for('index'))
    form = SignupForm()
    if form.validate_on_submit():
        username_check = User.query.filter_by(username=form.email.data).first()
        if username_check is not None:
            flash('An account already exists for ' + form.email.data + '. Please log in.', 'error')
            return redirect(url_for('login', email=form.email.data))
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
        email=form.email.data)
        #user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_password_email(user)
        flash('Welcome to Zaplings! Please check your inbox at ' + user.email + ' to finish setting up your account.')
        return redirect(url_for('index'))
    return render_template('signup.html', title='Sign up', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already signed in')
        return redirect(url_for('index'))
    form = LoginForm()
    if request.method == 'GET' and 'email' in request.args:
        form.email.data = request.args.get('email')
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if 'idea' in request.args:
            idea = request.args.get('idea')
        else:
            idea = ''
        if user and user.password_hash is None:
            send_password_email(user)
            flash('Please check your inbox at ' + user.email + ' to finish setting up your account.', 'error')
            return redirect(url_for('login', email=user.email, idea=idea))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login', idea=idea))
        login_user(user, remember=form.remember_me.data)
        next = request.args.get('next')
        if not next or url_parse(next).netloc != '':
            if idea != '':
                next = url_for('idea', idea=idea, id=user.id)
            else:
                next = url_for('home', id=user.id)
        return redirect(next)
    return render_template('login.html', title="Login", form=form)


@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_email(user, 'reset')
        flash('Check your email for instructions to reset your password.')
        return redirect(url_for('login'))
    return render_template('request-password-reset.html', title='Reset password', form=form)


@app.route('/set_password/<token>', methods=['GET', 'POST'])
def set_password(token):
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        login_user(user)
        flash('Your password has been updated successfully.')
        return redirect(url_for('home', id=user.id))
    return render_template('set-password.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    form = UserForm()
    users = User.query.filter_by(is_admin=False).order_by(User.first_name)
    admins = User.query.filter_by(is_admin=True).order_by(User.first_name)
    print(admins)
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
        email=form.email.data, phone=form.phone.data, about_me=form.about_me.data, \
        is_admin=form.is_admin.data)
        try:
            db.session.add(user)
            db.session.commit()
            flash(user.first_name + ' added')
        except:
            db.session.rollback()
            flash(user.first_name + ' could not be added', 'error')
            return redirect(url_for('users'))
        return redirect(url_for('users'))
    return render_template('users.html', title="Users", form=form, users=users, admins=admins)

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    form = UserForm()
    user = User.query.get_or_404(id)
    if form.validate_on_submit():
        if 'save' in request.form:
            user.first_name=form.first_name.data
            user.last_name=form.last_name.data
            user.email=form.email.data
            user.phone=form.phone.data
            user.about_me=form.about_me.data
            user.is_admin=form.is_admin.data
            try:
                db.session.add(user)
                db.session.commit()
                flash(user.first_name + ' updated')
            except:
                db.session.rollback()
                flash(user.first_name + ' could not be updated', 'error')
                return redirect(url_for('users'))
            finally:
                db.session.close()
        elif 'delete' in request.form:
            db.session.delete(user)
            db.session.commit()
            flash('Deleted ' + user.first_name)
        else:
            flash('Code error in POST request', 'error')
        return redirect(url_for('users'))
    elif request.method == "GET":
        form.first_name.data=user.first_name
        form.last_name.data=user.last_name
        form.email.data=user.email
        form.phone.data=user.phone
        form.about_me.data=user.about_me
        form.is_admin.data=user.is_admin
    return render_template('edit-user.html', title='Edit User', form=form, user=user)


@app.route("/download/<filename>")
def download_file (filename):
    path = os.path.join(app.root_path, 'static/files/')
    return send_from_directory(path, filename, as_attachment=False)


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('profile.html', user=user, posts=posts)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/favicon.ico')

@app.route('/manifest.webmanifest')
def webmanifest():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'img/favicons/manifest.webmanifest')

@app.route('/robots.txt')
@app.route('/sitemap.xml')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])
