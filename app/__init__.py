import os
import sys
from datetime import timedelta
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from flask_talisman import Talisman
from app.extensions import db, login_manager, csrf, limiter

def create_app():
    app = Flask(__name__)

    # FIX: No hardcoded secret key. Uses environment variable or generates a secure random one.
    app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # FIX: ProxyFix prevents IP spoofing in the audit logs
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = 'auth.login'

    csp = {
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
        'img-src': ["'self'", "data:", "blob:", "https://*.trycloudflare.com"],
        'script-src': ["'self'", "'unsafe-inline'"]
    }
    Talisman(app, content_security_policy=csp, frame_options='DENY')

    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.auth import auth_bp
    from app.admin import admin_bp
    from app.views import views_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(views_bp)

    with app.app_context():
        try:
            db.create_all()
            
            try:
                db.session.execute(text('SELECT is_admin FROM "user" LIMIT 1'))
            except Exception:
                db.session.rollback()
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT FALSE'))
                db.session.commit()
            
            try:
                db.session.execute(text('SELECT totp_secret FROM "user" LIMIT 1'))
            except Exception:
                db.session.rollback()
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN totp_secret VARCHAR(32)'))
                db.session.commit()

            try:
                db.session.execute(text('SELECT user_id FROM audit_log LIMIT 1'))
            except Exception:
                db.session.rollback()
                db.session.execute(text('ALTER TABLE audit_log ADD COLUMN user_id INTEGER REFERENCES "user"(id)'))
                db.session.commit()

            # FIX: No hardcoded 'password123'. Admin is only created if variables exist in Railway.
            admin_user = os.environ.get('ADMIN_USER')
            admin_pass = os.environ.get('ADMIN_PASS')
            
            if admin_user and admin_pass:
                master_admin = User.query.filter_by(username=admin_user).first()
                if not master_admin:
                    new_admin = User(
                        username=admin_user,
                        password_hash=generate_password_hash(admin_pass),
                        is_admin=True
                    )
                    db.session.add(new_admin)
                else:
                    master_admin.is_admin = True
                db.session.commit()
            
        except Exception:
            pass

    return app