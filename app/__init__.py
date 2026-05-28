import os
import sys
from datetime import timedelta
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from app.extensions import db, login_manager


def create_app():
    app = Flask(__name__)

    # ---------------------------------------------------------------
    # FIX 1: No fallback secret key — app refuses to start if unset.
    # Set FLASK_SECRET_KEY in your .env to a long random string.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    # ---------------------------------------------------------------
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    if not secret_key:
        sys.exit("ERROR: FLASK_SECRET_KEY environment variable is not set. Refusing to start.")
    app.secret_key = secret_key

    # ---------------------------------------------------------------
    # FIX 2 (partial): Session hardening
    # ---------------------------------------------------------------
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # FIX: prevents CSRF via cookie

    # ---------------------------------------------------------------
    # FIX 7: ProxyFix so request.remote_addr reflects the real client
    # IP behind Heroku / Nginx / any reverse proxy.
    # ---------------------------------------------------------------
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db_url = os.environ.get('DATABASE_URL')
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

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

            # Schema migrations (fragile try/except — ideally replace with Flask-Migrate)
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

            # ---------------------------------------------------------------
            # FIX 3: No hardcoded admin password fallback.
            # Both ADMIN_USER and ADMIN_PASS MUST be set in the environment.
            # ---------------------------------------------------------------
            admin_user = os.environ.get('ADMIN_USER')
            admin_pass = os.environ.get('ADMIN_PASS')

            if not admin_user or not admin_pass:
                sys.exit("ERROR: ADMIN_USER and ADMIN_PASS environment variables must be set.")

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

        except SystemExit:
            raise
        except Exception:
            pass

    return app