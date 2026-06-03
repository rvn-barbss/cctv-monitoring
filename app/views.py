import os
import cv2
import threading
import time
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, session, abort, Response
from flask_login import login_required, current_user
from app.models import User, AuditLog, BlockedIP
from app.utils import record_activity

views_bp = Blueprint('views', __name__)

@views_bp.route('/')
def index():
    return redirect(url_for('auth.login'))

@views_bp.route('/dashboard', strict_slashes=False, methods=['GET', 'POST'])
@login_required
def dashboard():
    if not session.get('camera_logged'):
        record_activity("ACCESSED LIVE CAMERA FEED", current_user.id)
        session['camera_logged'] = True

    all_users = User.query.all() if current_user.is_admin else []
    blocked_ips = BlockedIP.query.all() if current_user.is_admin else []
    
    active_ips = []
    if current_user.is_admin:
        recent_logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(200).all()
        blocked_set = {b.ip_address for b in blocked_ips}
        seen = set()
        
        for log in recent_logs:
            ip = log.ip_address
            if ip and ip not in seen and ip not in blocked_set:
                active_ips.append({
                    'ip': ip,
                    'action': log.action,
                    'user': log.user.username if log.user else 'Unknown'
                })
                seen.add(ip)
            if len(active_ips) >= 5:
                break
    
    # URL is securely pulled from environment only for authenticated users
    cam_url = os.environ.get('CAM_URL', '') 
    
    return render_template('camera.html', is_admin=current_user.is_admin, all_users=all_users, blocked_ips=blocked_ips, active_ips=active_ips, cam_url=cam_url)

@views_bp.route('/get_logs', strict_slashes=False)
@login_required
def get_logs():
    if not current_user.is_admin:
        abort(403)

    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
    
    lines = []
    for log in logs:
        ts = log.timestamp if log.timestamp else datetime.utcnow()
        ph_time = ts + timedelta(hours=8)
        time_str = ph_time.strftime("%Y-%m-%d %H:%M:%S")
        
        username = (log.user.username if log.user else "Unknown").replace('<', '&lt;').replace('>', '&gt;')
        action_str = (log.action if log.action else "Unknown Action").replace('<', '&lt;').replace('>', '&gt;')
        ip = (log.ip_address if log.ip_address else "Unknown IP").replace('<', '&lt;').replace('>', '&gt;')
        
        lines.append(f"[{time_str} UTC+8] {username} - {action_str} ({ip})")

    output = "\n".join(lines) if lines else "No activity recorded yet."
    return Response(output, mimetype='text/plain')

global_frame = None
stream_lock = threading.Lock()
camera_thread = None

def capture_rtsp_stream():
    global global_frame
    rtsp_url = os.environ.get('CCTV_RTSP_URL')
    
    if not rtsp_url:
        print("ERROR: CCTV_RTSP_URL not set in environment variables.")
        return

    camera = cv2.VideoCapture(rtsp_url)
    
    while True:
        success, frame = camera.read()
        if not success:
            print("Stream dropped. Reconnecting...")
            camera.release()
            time.sleep(2) 
            camera = cv2.VideoCapture(rtsp_url)
            continue
            
        ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
        if ret:
            with stream_lock:
                global_frame = buffer.tobytes()

def generate_frames():
    global global_frame, camera_thread
    
    if camera_thread is None:
        camera_thread = threading.Thread(target=capture_rtsp_stream, daemon=True)
        camera_thread.start()
        time.sleep(1) 
        
    while True:
        with stream_lock:
            frame_to_send = global_frame
            
        if frame_to_send is not None:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_to_send + b'\r\n')
        else:
            time.sleep(0.1) 
            
        time.sleep(0.05)

@views_bp.route('/video_feed')
@login_required 
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@views_bp.route('/<path:path>')
def catch_all(path):
    suspicious = ['wp-admin', '.env', 'phpmyadmin', 'config', 'admin.php', 'setup', '.git', 'passwd']
    
    if any(s in path.lower() for s in suspicious):
        from app.auth import add_ip_strike
        add_ip_strike(custom_reason=f"Honeypot tripped: Enumeration of /{path}", force_ban=True)
        abort(403, description="Active Defense Protocol: Malicious directory enumeration detected. IP blacklisted.")
        
    abort(404)
