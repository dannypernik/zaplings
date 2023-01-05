import os
from flask import Flask, render_template, flash, Markup, redirect, url_for, \
    request, send_from_directory, send_file, abort
from app import app, db, login, hcaptcha
from app.forms import SignupForm, LoginForm, IntroForm, InquiryForm, IdeaForm, \
    LovesForm, OffersForm, NeedsForm, UserForm, RequestPasswordResetForm, \
    ResetPasswordForm, ShareForm
from flask_login import current_user, login_user, logout_user, login_required, login_url
from app.models import User, Idea
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from datetime import datetime
from app.email import send_contact_email, send_verification_email, send_password_reset_email, \
    send_test_strategies_email, send_score_analysis_email, send_practice_test_email
from functools import wraps
import magic


app.config['UPLOAD_EXTENSIONS'] = ['image/png', 'image/jpeg']
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['STATIC_PATH'] = 'app/static'
app.config['IDEA_IMG_PATH'] = 'img/ideas'

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_viewed = datetime.utcnow()
        db.session.commit()

def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f))
                   for root_path, dirs, files in os.walk(folder)
                   for f in files))

@app.context_processor
def inject_values():
    return dict(last_updated=dir_last_updated('app/static'))

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

def validate_image(file):
    format = magic.from_buffer(file.read(1024), mime=True)
    file.stream.seek(0)
    if not format:
        return None
    return format


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = IntroForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        username_check = User.query.filter_by(username=form.email.data).first()
        if username_check is not None:
            if username_check.password_hash is None:
                send_verification_email(username_check)
                flash('You need to verify your email before saving more ideas. Please check your inbox.', 'error')
                return redirect(url_for('login', email=form.email.data))
            flash('An account already exists for ' + form.email.data + '. Please log in.', 'error')
            return redirect(url_for('login', email=form.email.data, idea=form.description.data))
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, \
            email=form.email.data, username=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        idea = Idea(description=form.description.data, creator_id=user.id)
        db.session.add(idea)
        db.session.commit()
        login_user(user)
        send_verification_email(user)
        flash('Welcome to Zaplings! Please check your inbox to verify that ' + user.email + ' is your email address.')
        return redirect(url_for('loves'))
    return render_template('index.html', form=form)


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
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
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
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'error')
            return redirect(url_for('login', idea=idea))
        login_user(user)
        next = request.args.get('next')
        if not next or url_parse(next).netloc != '':
            if idea != '':
                next = url_for('idea', idea=idea)
            else:
                next = url_for('home')
        if not user.is_verified:
            send_verification_email(user)
            flash('Please check your inbox at ' + user.email + ' to verify your account.')
        return redirect(next)
    return render_template('login.html', title="Login", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/verify_email/<token>', methods=['GET', 'POST'])
def verify_email(token):
    logout_user()
    user = User.verify_email_token(token)
    if user:
        user.is_verified = True
        db.session.add(user)
        db.session.commit()
        flash('Thank you for verifying your account.')
        login_user(user)
        return redirect(url_for('home'))
    else:
        flash('Your verification token is expired or invalid. Please log in to generate a new token.')
        return redirect(url_for('login'))


@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for instructions to reset your password.')
        return redirect(url_for('login'))
    return render_template('request-password-reset.html', title='Reset password', form=form)


@app.route('/set_password/<token>', methods=['GET', 'POST'])
def set_password(token):
    user = User.verify_email_token(token)
    if not user:
        flash('Verification has expired or is invalid. Please try again.')
        return redirect(url_for('request_password_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        login_user(user)
        flash('Your password has been updated successfully.')
        return redirect(url_for('home'))
    return render_template('set-password.html', form=form)


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
    form = ShareForm()
    ideas = Idea.query.filter_by(creator_id=current_user.get_id())
    return render_template('home.html', title="Home", form=form, ideas=ideas, \
        current_user=current_user)


@app.route('/create-zapling/<int:id>', methods=['GET', 'POST'])
@login_required
def create_zapling(id):
    form = IdeaForm()
    idea = Idea.query.get_or_404(id)
    primary_color = idea.primary_color or '#2a4776'
    secondary_color = idea.secondary_color or '#30b732'
    if current_user.get_id() != str(idea.creator_id):
        abort(403)
    else:
        if form.validate_on_submit():
            idea.name = form.name.data
            idea.tagline = form.tagline.data
            idea.description = form.description.data
            idea.primary_color = form.primary_color.data
            idea.secondary_color = form.secondary_color.data
            uploaded_file = request.files['logo']
            filename = uploaded_file.filename
            if filename != '':
                file_ext = os.path.splitext(filename)[1]
                if validate_image(uploaded_file) not in app.config['UPLOAD_EXTENSIONS']:
                    flash('Logo must be a PNG or JPEG image')
                    return redirect(url_for('create_zapling', id=idea.id))
                idea.logo = os.path.join(app.config['IDEA_IMG_PATH'], 'logo', str(id) + file_ext )
                uploaded_file.save(os.path.join(app.config['STATIC_PATH'], idea.logo))
            try:
                db.session.add(idea)
                db.session.commit()
                flash(idea.name + ' updated')
                return redirect(url_for('zapling', id=idea.id))
            except:
                db.session.rollback()
                flash(idea.name + ' could not be updated', 'error')
                return redirect(url_for('create_zapling', id=idea.id))
        elif request.method == 'GET':
            form.name.data = idea.name
            form.tagline.data = idea.tagline
            form.description.data = idea.description
            form.logo.data = idea.logo
            form.primary_color.data = primary_color
            form.secondary_color.data = secondary_color
    return render_template('create-zapling.html', form=form, \
        primary_color=primary_color, secondary_color=secondary_color)


@app.route('/zapling/<int:id>')
def zapling(id):
    form = InquiryForm()
    share_form = ShareForm()
    idea = Idea.query.get_or_404(id)
    if idea.primary_color is None:
        primary_color = '#2a4776'
        secondary_color = '#4ad1cc'
    else:
        primary_color = idea.primary_color
        secondary_color = idea.secondary_color
    return render_template('zapling.html', title="New zapling", form=form, current_user=current_user, \
        idea=idea, primary_color=primary_color, secondary_color=secondary_color)


@app.route('/loves', methods=['GET', 'POST'])
@login_required
def loves():
    form = LovesForm()
    if form.validate_on_submit():
        current_user.loves = form.loves.data
        db.session.add(current_user)
        db.session.commit()
        flash('Passions updated')
        if current_user.needs is None:
            return redirect(url_for('needs'))
        elif current_user.offers is None:
            return redirect(url_for('offers'))
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.loves.data = current_user.loves
    return render_template('loves.html', form=form)


@app.route('/needs', methods=['GET', 'POST'])
@login_required
def needs():
    form = NeedsForm()
    if form.validate_on_submit():
        current_user.needs = form.needs.data
        db.session.add(current_user)
        db.session.commit()
        flash('Needs updated')
        if current_user.offers is None:
            return redirect(url_for('offers'))
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.needs.data = current_user.needs
    return render_template('needs.html', form=form)


@app.route('/offers', methods=['GET', 'POST'])
@login_required
def offers():
    form = OffersForm()
    if form.validate_on_submit():
        current_user.offers = form.offers.data
        db.session.add(current_user)
        db.session.commit()
        flash('Offers updated')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.offers.data = current_user.offers
    return render_template('offers.html', form=form)


@app.route('/availability')
@login_required
def availability():
    wkd = ['mondays','tuesdays','wednesdays','thursdays','fridays']
    wke = ['saturdays', 'sundays']
    weeks = ['weekdays', 'weekends']
    return render_template('availability.html', title="Availability", wkd=wkd, wke=wke, weeks=weeks)


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
