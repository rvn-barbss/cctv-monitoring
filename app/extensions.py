from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect   # FIX 4: CSRF protection

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()                     # FIX 4: instantiate here, init in create_app()