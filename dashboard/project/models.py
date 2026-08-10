from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model for storing user credentials.

    Attributes:
        id (int): User ID.
        username (str): Username.
        password (str): Password hash.
        votes (list): Votes cast by the user.
    """

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    # Cascade deletion
    votes = db.relationship('Vote', backref='user', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Vote(db.Model):
    """
    Vote model for storing votes.

    Attributes:
        id (int): Vote ID.
        user_id (int): User ID.
        vote (int): Vote value.
        meta_id (str): Metadata ID.
        vote_date (datetime): Vote date.
    """

    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vote = db.Column(db.Integer, nullable=False)
    meta_id = db.Column(db.String(255), nullable=False)

    vote_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
