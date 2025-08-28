from flask import Flask, render_template, redirect, url_for, flash, request, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from datetime import datetime, timedelta
import pytz
import os
import csv
from io import StringIO  # For in-memory CSV generation

app = Flask(__name__)
import os
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db').replace("postgres://", "postgresql://", 1)  # Render fix
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Custom Jinja filter for datetime
def datetimefilter(value):
    if value:
        return value.strftime('%Y-%m-%d %H:%M:%S') + ' IST'
    return 'N/A'

app.jinja_env.filters['datetimefilter'] = datetimefilter

# Define models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')

    def set_password(self, password):
        """Hash and set the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hashed password."""
        return check_password_hash(self.password_hash, password)

    breaks = db.relationship('BreakLog', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"

class BreakLog(db.Model):
    __tablename__ = 'break_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    break_type = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)

    def __repr__(self):
        return f"<BreakLog {self.break_type} for User ID {self.user_id}>"

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddEmployeeForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Add Employee')

class BreakForm(FlaskForm):
    break_type = SelectField('Break Type', choices=[('1st Break', '1st Break'), ('2nd Break', '2nd Break'), ('Dinner Break', 'Dinner Break'), ('Bathroom Break', 'Bathroom Break')], validators=[DataRequired()])
    submit = SubmitField('Start Break')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')

class EditEmployeeForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Update Employee')

class DateRangeForm(FlaskForm):
    start_date = DateField('Start Date', validators=[DataRequired()], format='%Y-%m-%d')
    end_date = DateField('End Date', validators=[DataRequired()], format='%Y-%m-%d')
    submit = SubmitField('View Report')

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):  # Use check_password method
            login_user(user)
            flash('Login successful!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/employee/dashboard', methods=['GET', 'POST'])
@login_required
def employee_dashboard():
    if current_user.role != 'employee':
        return redirect(url_for('admin_dashboard'))
    
    form = BreakForm()
    active_break = BreakLog.query.filter_by(user_id=current_user.id, end_time=None).first()
    
    ist = pytz.timezone('Asia/Kolkata')
    
    if form.validate_on_submit():
        if active_break:
            flash('You already have an active break. End it first.', 'warning')
        else:
            new_break = BreakLog(user_id=current_user.id, break_type=form.break_type.data, start_time=datetime.now(ist))
            db.session.add(new_break)
            db.session.commit()
            flash('Break started!', 'success')
            return redirect(url_for('employee_dashboard'))
    
    if request.method == 'POST' and 'end_break' in request.form:
        if active_break:
            active_break.end_time = datetime.now(ist)
            db.session.commit()
            flash('Break ended!', 'success')
        return redirect(url_for('employee_dashboard'))
    
    my_breaks = BreakLog.query.filter_by(user_id=current_user.id).order_by(BreakLog.start_time.desc()).limit(10).all()
    return render_template('employee_dashboard.html', form=form, active_break=active_break, my_breaks=my_breaks)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    employees = User.query.filter_by(role='employee').all()
    return render_template('admin_dashboard.html', employees=employees)

@app.route('/admin/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    form = AddEmployeeForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
        else:
            user = User(username=form.username.data, role='employee')
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Employee added successfully!', 'success')
            print(f"Added user: {user.username}, password_hash: {user.password_hash}")
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
        if form.username.data != user.username:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return render_template('edit_employee.html', form=form, user=user)
        
        user.username = form.username.data
        if form.new_password.data:
            user.set_password(form.new_password.data)  # Use set_password
        db.session.commit()
        flash('Employee details updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    form.username.data = user.username
    return render_template('edit_employee.html', form=form, user=user)

@app.route('/admin/delete_employee/<int:user_id>')
@login_required
def delete_employee(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    user = User.query.get_or_404(user_id)
    if user.role == 'employee':
        # Reassign break logs to a default user (e.g., admin with id=1)
        default_user_id = 1  # Ensure this user exists
        db.session.query(BreakLog).filter_by(user_id=user_id).update({BreakLog.user_id: default_user_id})
        # Delete the employee
        db.session.delete(user)
        db.session.commit()
        flash('Employee deleted, their break logs reassigned to default user.', 'success')
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/break_logs')
@login_required
def break_logs():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    logs = BreakLog.query.order_by(BreakLog.start_time.desc()).all()
    return render_template('break_logs.html', logs=logs)

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
        
        ist = pytz.timezone('Asia/Kolkata')
        start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=ist)
        end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=ist)
        
        logs = BreakLog.query.join(User).filter(
            BreakLog.start_time >= start_datetime,
            BreakLog.start_time <= end_datetime
        ).order_by(BreakLog.start_time.desc()).all()
        
        flash(f'Showing break logs from {start_date} to {end_date}.', 'info')
    
    return render_template('date_filtered_break_logs.html', form=form, logs=logs, start_date=start_date, end_date=end_date)

@app.route('/admin/download_date_filtered_report', methods=['POST'])
@login_required
def download_date_filtered_report():
    if current_user.role != 'admin':
        return redirect(url_for('date_filtered_break_logs'))
    
    form = DateRangeForm()
    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        if start_date > end_date:
            flash('Start date cannot be after end date.', 'danger')
            return redirect(url_for('date_filtered_break_logs'))
        
        ist = pytz.timezone('Asia/Kolkata')
        start_datetime = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=ist)
        end_datetime = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=ist)
        
        logs = BreakLog.query.join(User).filter(
            BreakLog.start_time >= start_datetime,
            BreakLog.start_time <= end_datetime
        ).order_by(BreakLog.start_time.desc()).all()
        
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Employee Username', 'Break Type', 'Start Time (IST)', 'End Time (IST)', 'Duration'])
        for log in logs:
            duration = (
                f"{int((log.end_time - log.start_time).total_seconds() // 60)} minute{'s' if (log.end_time - log.start_time).total_seconds() // 60 != 1 else ''} "
                f"{int((log.end_time - log.start_time).total_seconds() % 60)} second{'s' if (log.end_time - log.start_time).total_seconds() % 60 != 1 else ''}"
            ) if log.end_time else 'Ongoing'
            start_time_str = log.start_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.start_time else 'N/A'
            end_time_str = log.end_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.end_time else 'N/A'
            cw.writerow([log.user.username, log.break_type, start_time_str, end_time_str, duration])
        
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=break_report_{start_date}_to_{end_date}.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    
    flash('Invalid date range.', 'danger')
    return redirect(url_for('date_filtered_break_logs'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):  # Use check_password
            if form.new_password.data == form.current_password.data:
                flash('New password cannot be the same as the current password.', 'danger')
            else:
                current_user.set_password(form.new_password.data)  # Use set_password
                db.session.commit()
                flash('Password changed successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Current password is incorrect.', 'danger')
    return render_template('change_password.html', form=form)

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
        duration = (
            f"{int((log.end_time - log.start_time).total_seconds() // 60)} minute{'s' if (log.end_time - log.start_time).total_seconds() // 60 != 1 else ''} "
            f"{int((log.end_time - log.start_time).total_seconds() % 60)} second{'s' if (log.end_time - log.start_time).total_seconds() % 60 != 1 else ''}"
        ) if log.end_time else 'Ongoing'
        start_time_str = log.start_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.start_time else 'N/A'
        end_time_str = log.end_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.end_time else 'N/A'
        cw.writerow([user.username, log.break_type, start_time_str, end_time_str, duration])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={user.username}_break_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/download_all_reports')
@login_required
def download_all_reports():
    if current_user.role != 'admin':
        return redirect(url_for('employee_dashboard'))
    
    logs = BreakLog.query.join(User).order_by(User.username, BreakLog.start_time.desc()).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Employee Username', 'Break Type', 'Start Time (IST)', 'End Time (IST)', 'Duration'])
    for log in logs:
        duration = (
            f"{int((log.end_time - log.start_time).total_seconds() // 60)} minute{'s' if (log.end_time - log.start_time).total_seconds() // 60 != 1 else ''} "
            f"{int((log.end_time - log.start_time).total_seconds() % 60)} second{'s' if (log.end_time - log.start_time).total_seconds() % 60 != 1 else ''}"
        ) if log.end_time else 'Ongoing'
        start_time_str = log.start_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.start_time else 'N/A'
        end_time_str = log.end_time.strftime('%Y-%m-%d %H:%M:%S') + ' IST' if log.end_time else 'N/A'
        cw.writerow([log.user.username, log.break_type, start_time_str, end_time_str, duration])
    
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=all_employees_break_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Initialize DB with admin user if not exists
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)