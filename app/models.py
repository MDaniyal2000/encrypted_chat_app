import datetime
from flask_login import UserMixin
from app import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Users
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer(), nullable=False, primary_key=True)
    username = db.Column(db.String(), unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    p_value = db.Column(db.Integer(), nullable=False)
    q_value = db.Column(db.Integer(), nullable=False)
    e_value = db.Column(db.Integer(), nullable=False)
    d_value = db.Column(db.Integer(), nullable=False)
    n_value = db.Column(db.Integer(), nullable=False)

    def get_id(self):
        return (self.user_id)

#Conversations
class Conversation(db.Model):
    __tablename__ = 'conversations'
    conversation_id = db.Column(db.Integer(), nullable=False, primary_key=True)
    user1_id = db.Column(db.Integer(), nullable=False)
    user2_id = db.Column(db.Integer(), nullable=False)
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    messages = db.relationship('Message', backref='of_conversation', cascade='all,delete', lazy='dynamic')

#Messages
class Message(db.Model):
    __tablename__ = 'messages'
    message_id = db.Column(db.Integer(), nullable=False, primary_key=True)
    conversation_id = db.Column(db.Integer(), db.ForeignKey('conversations.conversation_id'), nullable=False)
    sender_id = db.Column(db.Integer(), nullable=False)
    receiver_id = db.Column(db.Integer(), nullable=False)
    sender_copy = db.Column(db.String(), nullable=False)
    receiver_copy = db.Column(db.String(), nullable=False)
    is_image = db.Column(db.Boolean(), nullable=False, default=False)
    sent_dt = db.Column(db.DateTime(), nullable=False, default=datetime.datetime.utcnow)
