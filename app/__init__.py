import os
from datetime import timedelta
from flask import Flask, request, abort
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from flask_talisman import Talisman
from app.extensions import db, login_manager, csrf, limiter

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET_KEY')
    
    if not app.secret_key:
        raise ValueError("FATAL: FLASK_SECRET_KEY environment variable is not set.")

    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
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

    # UPDATED: Relaxed CSP to allow Cloudflare HLS streaming and jsDelivr scripts
    csp = {
        'default-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
        'img-src': ["'self'", "data:", "blob:", "https://*.trycloudflare.com"],
        'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        'connect-src': ["'self'", "https://*.trycloudflare.com"],
        'media-src': ["'self'", "blob:", "https://*.trycloudflare.com"]
    }
    Talisman(app, content_security_policy=csp, frame_options='DENY', content_security_policy_nonce_in=[])

    from app.models import User, BlockedIP
    
    @app.before_request
    def block_malicious_ips():
        if request.headers.get('CF-Connecting-IP'):
            ip = request.headers.get('CF-Connecting-IP').strip()
        elif request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip = request.remote_addr
            
        is_blocked = BlockedIP.query.filter_by(ip_address=ip).first()
        if is_blocked:
            abort(403, description=f"ERR_ACCESS_DENIED: Your IP address ({ip}) has been permanently blacklisted. Reason: {is_blocked.reason}")

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
            
            # --- DATABASE MIGRATIONS ---
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
                
            # FIX: Force PostgreSQL to create the missing Threat Tracking columns!
            try:
                db.session.execute(text('SELECT event_code FROM audit_log LIMIT 1'))
            except Exception:
                db.session.rollback()
                db.session.execute(text("ALTER TABLE audit_log ADD COLUMN event_code VARCHAR(32) DEFAULT 'SYS_EVENT'"))
                db.session.execute(text("ALTER TABLE audit_log ADD COLUMN severity VARCHAR(16) DEFAULT 'INFO'"))
                db.session.commit()

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
        except Exception as e:
            print(f"Startup Database Error: {e}")

    return app
