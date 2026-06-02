from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# INCREASED LIMITS to allow the live dashboard to poll for logs safely
limiter = Limiter(
    key_func=get_remote_address, 
    default_limits=["5000 per day", "1000 per hour"]
)
