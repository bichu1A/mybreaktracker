from flask import (
    Flask, render_template, redirect, url_for, flash, request, make_response, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from datetime import datetime, timedelta
import pytz
import os
import csv
from io import StringIO
from flask_migrate import Migrate
import logging

# ----------------------------
# Logging configuration
# ----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------------------
# Flask App & Config
# -------------------------------------
app = Flask(__name__)

# SECRET_KEY comes from env in production (Render)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'fallback-secret-only-for-local-dev'
)

# Database URL: Enforce PostgreSQL from environment
db_url = os.environ.get("DATABASE_URL")
if not db_url or not db_url.startswith("postgresql://"):
    raise ValueError("DATABASE_URL environment variable must be set and start with postgresql://")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ----------------------------
# Initialize DB and Migrate
# ----------------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ----------------------------
# Login Manager
# ----------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ----------------------------
# Timezone
# ----------------------------
IST = pytz.timezone('Asia/Kolkata')

def now_ist():
    return datetime.now(IST)

def fmt_ist(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if dt else 'N/A'

# ----------------------------
# Jinja Filters
# ----------------------------
app.jinja_env.filters['datetimefilter'] = fmt_ist

# -------------------------------------
# Database Models
# -------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')
    active = db.Column(db.Boolean, default=True)
    breaks = db.relationship('BreakLog', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

class BreakLog(db.Model):
    __tablename__ = 'break_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    break_type = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)

    def duration(self):
        if self.end_time:
            delta = self.end_time - self.start_time
            minutes = delta.seconds // 60
            seconds = delta.seconds % 60
            return f"{minutes}m {seconds}s"
        return "Ongoing"

    def __repr__(self):
        return f"<BreakLog {self.break_type} by {self.user_id}>"

# -------------------------------------
# Forms
# -------------------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddEmployeeForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Add Employee')

class EditEmployeeForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password')])
    active = BooleanField('Active')
    submit = SubmitField('Update Employee')

class BreakForm(FlaskForm):
    break_type = SelectField('Break Type', choices=[
        ('1st Break','1st Break'),
        ('2nd Break','2nd Break'),
        ('Dinner Break','Dinner Break'),
        ('Bathroom Break','Bathroom Break')
    ], validators=[DataRequired()])
    submit = SubmitField('Start Break')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class DateRangeForm(FlaskForm):
    start_date = DateField('Start Date', validators=[DataRequired()], format='%Y-%m-%d')
    end_date = DateField('End Date', validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField('View Report')

# -------------------------------------
# Load User
# -------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------------------
# Initialization Function
# -------------------------------------
def init_db_and_admin():
    """Initialize DB and create default admin if not exists."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', active=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin created with username: 'admin', password: 'admin123'")

# -------------------------------------
# Routes: Auth
# -------------------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard') if current_user.role=='admin' else 'employee_dashboard')
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.check_password(form.password.data):
            if not user.active:
                flash('Account inactive. Contact admin.', 'danger')
            else:
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('admin_dashboard') if user.role=='admin' else 'employee_dashboard')
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ---------- Employee ----------
@app.route('/employee/dashboard', methods=['GET', 'POST'])
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        return redirect(url_for('admin_dashboard'))

    form = BreakForm()
    active_break = BreakLog.query.filter_by(user_id=current_user.id, end_time=None).first()

    if form.validate_on_submit():
        if active_break:
            flash('You already have an active break. End it first.', 'warning')
        else:
            new_break = BreakLog(
                user_id=current_user.id,
                break_type=form.break_type.data,
                start_time=now_ist()
            )
            db.session.add(new_break)
            db.session.commit()
            flash('Break started!', 'success')
            return redirect(url_for('employee_dashboard'))

    # Handle end break via POST button named 'end_break'
    if request.method == 'POST' and 'end_break' in request.form:
        if active_break:
            active_break.end_time = now_ist()
            db.session.commit()
            flash('Break ended!', 'success')
        return redirect(url_for('employee_dashboard'))

    my_breaks = (BreakLog.query
                 .filter_by(user_id=current_user.id)
                 .order_by(BreakLog.start_time.desc())
                 .limit(10).all())
    return render_template('employee_dashboard.html', form=form, active_break=active_break, my_breaks=my_breaks)

# ---------- Admin ----------
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    employees = User.query.filter_by(role='employee').order_by(User.username.asc()).all()
    return render_template('admin_dashboard.html', employees=employees)

@app.route('/admin/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    form = AddEmployeeForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            user = User(username=username, role='employee')
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Employee added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
    return render_template('add_employee.html', form=form)

@app.route('/admin/edit_employee/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_employee(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role != 'employee':
        flash('Can only edit employee accounts.', 'danger')
        return redirect(url_for('admin_dashboard'))

    form = EditEmployeeForm()
    if form.validate_on_submit():
        desired_username = form.username.data.strip()
        if desired_username != user.username:
            duplicate = User.query.filter_by(username=desired_username).first()
            if duplicate:
                flash('Username already exists.', 'danger')
                return render_template('edit_employee.html', form=form, user=user)

        user.username = desired_username
        if form.new_password.data:
            user.set_password(form.new_password.data)
        db.session.commit()
        flash('Employee details updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    # Pre-fill on initial GET
    if request.method == 'GET':
        form.username.data = user.username
    return render_template('edit_employee.html', form=form, user=user)

@app.route('/admin/delete_employee/<int:user_id>')
@login_required
def delete_employee(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role == 'employee':
        db.session.delete(user)
        db.session.commit()
        flash('Employee and their break logs were deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/break_logs')
@login_required
def break_logs():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    logs = BreakLog.query.order_by(BreakLog.start_time.desc()).all()
    return render_template('break_logs.html', logs=logs)

# ---------- Date Filtered Report ----------
@app.route('/admin/date_filtered_break_logs', methods=['GET', 'POST'])
@login_required
def date_filtered_break_logs():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    form = DateRangeForm()
    logs = []
    start_date = None
    end_date = None

    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        if start_date > end_date:
            flash('Start date cannot be after end date.', 'danger')
            return render_template('date_filtered_break_logs.html', form=form, logs=logs)

        start_datetime = IST.localize(datetime.combine(start_date, datetime.min.time()))
        end_datetime = IST.localize(datetime.combine(end_date, datetime.max.time()))

        logs = (BreakLog.query
                .join(User)
                .filter(BreakLog.start_time >= start_datetime,
                        BreakLog.start_time <= end_datetime)
                .order_by(BreakLog.start_time.desc())
                .all())

        flash(f'Showing break logs from {start_date} to {end_date}.', 'info')

    return render_template(
        'date_filtered_break_logs.html',
        form=form, logs=logs, start_date=start_date, end_date=end_date
    )

# ---------- CSV Downloads ----------
@app.route('/admin/download_date_filtered_report', methods=['POST'])
@login_required
def download_date_filtered_report():
    if current_user.role != 'admin':
        return redirect(url_for('date_filtered_break_logs'))

    form = DateRangeForm()
    if not form.validate_on_submit():
        flash('Invalid date range.', 'danger')
        return redirect(url_for('date_filtered_break_logs'))

    start_date = form.start_date.data
    end_date = form.end_date.data
    if start_date > end_date:
        flash('Start date cannot be after end date.', 'danger')
        return redirect(url_for('date_filtered_break_logs'))

    start_datetime = IST.localize(datetime.combine(start_date, datetime.min.time()))
    end_datetime = IST.localize(datetime.combine(end_date, datetime.max.time()))

    logs = (BreakLog.query
            .join(User)
            .filter(BreakLog.start_time >= start_datetime,
                    BreakLog.start_time <= end_datetime)
            .order_by(BreakLog.start_time.desc())
            .all())

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Employee Username', 'Break Type', 'Start Time (IST)', 'End Time (IST)', 'Duration'])
    for log in logs:
        if log.end_time:
            total_seconds = int((log.end_time - log.start_time).total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} minute{'s' if minutes != 1 else ''} {seconds} second{'s' if seconds != 1 else ''}"
        else:
            duration = 'Ongoing'
        cw.writerow([
            log.user.username,
            log.break_type,
            fmt_ist(log.start_time),
            fmt_ist(log.end_time),
            duration
        ])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=break_report_{start_date}_to_{end_date}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/download_employee_report/<int:user_id>')
@login_required
def download_employee_report(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    user = User.query.get_or_404(user_id)
    if user.role != 'employee':
        flash('Invalid employee.', 'danger')
        return redirect(url_for('admin_dashboard'))

    logs = BreakLog.query.filter_by(user_id=user_id).order_by(BreakLog.start_time.desc()).all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Employee Username', 'Break Type', 'Start Time (IST)', 'End Time (IST)', 'Duration'])
    for log in logs:
        if log.end_time:
            total_seconds = int((log.end_time - log.start_time).total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} minute{'s' if minutes != 1 else ''} {seconds} second{'s' if seconds != 1 else ''}"
        else:
            duration = 'Ongoing'
        cw.writerow([
            user.username,
            log.break_type,
            fmt_ist(log.start_time),
            fmt_ist(log.end_time),
            duration
        ])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={user.username}_break_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/download_all_reports')
@login_required
def download_all_reports():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    logs = (BreakLog.query
            .join(User)
            .order_by(User.username.asc(), BreakLog.start_time.desc())
            .all())

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Employee Username', 'Break Type', 'Start Time (IST)', 'End Time (IST)', 'Duration'])
    for log in logs:
        if log.end_time:
            total_seconds = int((log.end_time - log.start_time).total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            duration = f"{minutes} minute{'s' if minutes != 1 else ''} {seconds} second{'s' if seconds != 1 else ''}"
        else:
            duration = 'Ongoing'
        cw.writerow([
            log.user.username,
            log.break_type,
            fmt_ist(log.start_time),
            fmt_ist(log.end_time),
            duration
        ])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=all_employees_break_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# ---------- Admin password change ----------
@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html', form=form)

        if form.new_password.data == form.current_password.data:
            flash('New password cannot be the same as the current password.', 'danger')
            return render_template('change_password.html', form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('change_password.html', form=form)

# -------------------------------------
# Error Handler
# -------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# -------------------------------------
# One-time DB bootstrap (create tables + default admin)
# -------------------------------------
with app.app_context():
    db.create_all()
    init_db_and_admin()

# -------------------------------------
# Entrypoint
# -------------------------------------
if __name__ == '__main__':
    # On Render, gunicorn will run this app; for local dev, this line is fine.
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
