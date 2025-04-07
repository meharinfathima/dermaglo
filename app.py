from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    completed_questionnaire = db.Column(db.Boolean, default=False)
    routine = db.Column(db.JSON)  # Store the routine as JSON
    skin_type = db.Column(db.String(20))
    breakouts = db.Column(db.String(20))
    sensitivity = db.Column(db.String(20))
    concerns = db.Column(db.Text)

class RoutineProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    morning_routine_completed = db.Column(db.Boolean, default=False)
    evening_routine_completed = db.Column(db.Boolean, default=False)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')

class SkincareForm(FlaskForm):
    skin_type = RadioField(
        'What is your skin type?',
        choices=[
            ('dry', 'Dry'),
            ('oily', 'Oily'),
            ('combination', 'Combination'),
            ('sensitive', 'Sensitive')
        ],
        validators=[DataRequired()]
    )
    breakouts = RadioField(
        'How often do you experience breakouts?',
        choices=[
            ('rarely', 'Rarely'),
            ('sometimes', 'Sometimes'),
            ('often', 'Often')
        ],
        validators=[DataRequired()]
    )
    sensitivity = RadioField(
        'Is your skin sensitive?',
        choices=[
            ('yes', 'Yes'),
            ('no', 'No')
        ],
        validators=[DataRequired()]
    )
    concerns = SelectMultipleField(
        'Select your skin concerns:',
        choices=[
            ('acne', 'Acne'),
            ('wrinkles', 'Wrinkles'),
            ('dark_spots', 'Dark Spots'),
            ('dryness', 'Dryness')
        ],
        option_widget=widgets.CheckboxInput(),
        widget=widgets.ListWidget(prefix_label=False)
    )
    submit = SubmitField('Finish')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        if not current_user.completed_questionnaire:
            return redirect(url_for('questionnaire'))
        return redirect(url_for('routine'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)

            if not user.completed_questionnaire:
                return redirect(url_for('questionnaire'))

            return redirect(url_for('routine'))

        flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/questionnaire', methods=['GET', 'POST'])
@login_required
def questionnaire():
    form = SkincareForm()
    if form.validate_on_submit():
        print("Form submitted and validated successfully!")  # Debug statement
        print("Skin Type:", form.skin_type.data)  # Debug statement
        print("Breakouts:", form.breakouts.data)  # Debug statement
        print("Sensitivity:", form.sensitivity.data)  # Debug statement
        print("Concerns:", form.concerns.data)  # Debug statement

        current_user.skin_type = form.skin_type.data
        current_user.breakouts = form.breakouts.data
        current_user.sensitivity = form.sensitivity.data
        current_user.concerns = ",".join(form.concerns.data)  # Store as a comma-separated string
        current_user.completed_questionnaire = True

        # Generate routine based on skin type and concerns
        routine = generate_routine(current_user.skin_type, current_user.concerns)
        current_user.routine = routine  # Store the routine in the database
        db.session.commit()

        flash("Questionnaire submitted successfully!", "success")
        return redirect(url_for('routine'))
    else:
        print("Form validation failed!")  # Debug statement
        print(form.errors)  # Print form errors for debugging

    return render_template('questionnaire.html', form=form)

def generate_routine(skin_type, concerns_string):
    concerns = concerns_string.split(",")  # Convert stored string back to list

    routine = {
        "morning": [],
        "evening": []
    }

    # Base routine based on skin type
    if skin_type == "dry":
        routine["morning"].extend(["Hydrating Cleanser", "Moisturizer with SPF"])
        routine["evening"].extend(["Gentle Cleanser", "Night Cream"])
    elif skin_type == "oily":
        routine["morning"].extend(["Foaming Cleanser", "Oil-Free Moisturizer"])
        routine["evening"].extend(["Exfoliating Cleanser", "Lightweight Serum"])
    elif skin_type == "combination":
        routine["morning"].extend(["Balancing Cleanser", "Gel Moisturizer with SPF"])
        routine["evening"].extend(["Gentle Exfoliating Cleanser", "Night Serum"])
    elif skin_type == "sensitive":
        routine["morning"].extend(["Fragrance-Free Cleanser", "Soothing Moisturizer with SPF"])
        routine["evening"].extend(["Gentle Cleanser", "Calming Night Cream"])

    # Add treatments based on concerns
    if "acne" in concerns:
        routine["morning"].append("Salicylic Acid Treatment")
        routine["evening"].append("Benzoyl Peroxide Spot Treatment")
    
    if "wrinkles" in concerns:
        routine["morning"].append("Vitamin C Serum")
        routine["evening"].append("Retinol Cream")
    
    if "dark_spots" in concerns:
        routine["morning"].append("Brightening Serum")
        routine["evening"].append("Niacinamide Treatment")
    
    if "dryness" in concerns:
        routine["morning"].append("Hydrating Toner")
        routine["evening"].append("Hyaluronic Acid Serum")

    return routine


@app.route('/routine')
@login_required
def routine():
    if not current_user.completed_questionnaire:
        flash("Please complete the questionnaire first.", "warning")
        return redirect(url_for('questionnaire'))
    return render_template('routine.html', routine=current_user.routine)

@app.route('/daily_progress', methods=['GET', 'POST'])
@login_required
def daily_progress():
    if request.method == 'POST':
        date_str = request.form.get('date')  # Get the date string
        try:
            # Convert string to datetime.date object
            date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format. Please select a valid date.", "danger")
            return redirect(url_for('daily_progress'))

        morning_completed = 'morning_routine' in request.form
        evening_completed = 'evening_routine' in request.form

        print(f"Date: {date}, Morning: {morning_completed}, Evening: {evening_completed}")

        if date:
            progress = RoutineProgress(
                user_id=current_user.id,
                date=date,  # Pass the proper date object
                morning_routine_completed=morning_completed,
                evening_routine_completed=evening_completed
            )
            db.session.add(progress)
            db.session.commit()
            flash("Progress logged successfully!", "success")
        else:
            flash("Please select a valid date.", "danger")

        return redirect(url_for('daily_progress'))

    progress = RoutineProgress.query.filter_by(user_id=current_user.id).all()
    return render_template('daily_progress.html', progress=progress)

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)