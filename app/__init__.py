from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

#Initialize our app
app = Flask(__name__)

#Set database uri
app.config['SECRET_KEY'] = 'zs9XYCbTPKvux46UJckflw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost/chat_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG", "GIF"]
app.config["MAX_IMAGE_FILESIZE"] = 0.5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'app/static/images'

#Initialize db
db = SQLAlchemy(app)
#Initialize password hashing library
bcrypt = Bcrypt(app)
#Initialize user login session manager
login_manager = LoginManager(app)
#Redirect route for un-authorized users
login_manager.login_view = 'login'
#Bootstrap alert class for warning message
login_manager.login_message_category = 'info'

#Import routes
from app import routes
