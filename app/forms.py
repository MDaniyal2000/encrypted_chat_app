from app.models import User
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

#Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username is required')])
    email = StringField('Email', validators=[DataRequired(message='Email is required'), Email(message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Confirm Password is required'), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different one')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Please use a different one')

#Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message='Username is required')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

