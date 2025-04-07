from extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    skin_type = db.Column(db.String(20))  # Store the skin type
    breakouts = db.Column(db.String(20))
    sensitivity = db.Column(db.String(20))
    concerns = db.Column(db.String(200))  # Store multiple concerns

class RoutineProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    morning_routine_completed = db.Column(db.Boolean, default=False)
    evening_routine_completed = db.Column(db.Boolean, default=False)

