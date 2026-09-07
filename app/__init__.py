from __future__ import annotations
import base64, os, threading, time
from datetime import datetime, timezone
import bcrypt
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from flask_socketio import SocketIO
from . import db
from .realtime import register_socketio
from .security import admin_required, clean_text, client_ip, new_identity, rate_limit, require_csrf, require_identity, verify_admin
from .tasks import cleanup_expired
load_dotenv()

def build_app():
    app=Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY','dev-only-change-me'),SESSION_TTL=int(os.environ.get('SESSION_TTL_SECONDS','86400')),COOKIE_SECURE=os.environ.get('COOKIE_SECURE','false').lower()=='true',ADMIN_USERNAME=os.environ.get('ADMIN_USERNAME','anand'),ADMIN_PASSWORD_HASH=os.environ.get('ADMIN_PASSWORD_HASH','$2b$12$nioGBqfOWaSOYQd1T5MdkOZ6M4BkEgDt/S5zT4B9r3HwHVC/PmXei'),BLOCKED_IPS=set(),SECURITY_LOG=lambda e,d: None)
    raw=os.environ.get('MESSAGE_ENCRYPTION_KEY','')
    try: key=base64.urlsafe_b64decode(raw+'===')
    except Exception: key=b''
    if len(key)!=32: key=base64.urlsafe_b64encode(b'local-dev-key-change-me-32bytes!')[:32]
    app.config['MESSAGE_KEY']=key
    app.config['SESSION_COOKIE_HTTPONLY']=True; app.config['SESSION_COOKIE_SECURE']=app.config['COOKIE_SECURE']; app.config['SESSION_COOKIE_SAMESITE']='Lax'
    def security_log(event,detail):
        try: db.log_security(event,detail,client_ip(),None)
        except Exception: pass
    app.config['SECURITY_LOG']=security_log
    socketio=SocketIO(app,async_mode='eventlet',cors_allowed_origins=os.environ.get('CORS_ORIGINS','http://localhost:5000').split(','),logger=False,message_queue=os.environ.get('REDIS_URL'))
    @app.before_request
    def guard():
        if request.endpoint == 'api_admin_login':
            if not session.get('sid'): new_identity()
            return
        if request.endpoint and request.endpoint.startswith('api_'):
            require_identity(); require_csrf(); rate_limit('http',120,60)
    @app.get('/')
    def index():
        if not session.get('sid'): new_identity()
        return render_template('index.html',csrf=session['csrf'])
    @app.get('/admin')
    def admin():
        if not session.get('sid'): new_identity()
        return render_template('admin.html')
    @app.get('/healthz')
    def health(): return {'status':'ok'}
    @app.post('/api/session')
    def api_session():
        data=request.get_json(silent=True) or {}; name=clean_text(data.get('display_name'),40)
        if len(name)<2: return jsonify(error='Display name must be 2–40 characters'),400
        session['display_name']=name
        return jsonify(csrf=session['csrf'],display_name=name)
    @app.post('/api/channels')
    def api_create_channel():
        import bcrypt
        data=request.get_json(silent=True) or {}; code=clean_text(data.get('channel_id'),64); name=clean_text(data.get('name') or code,80); password=str(data.get('password') or '')
        minutes=int(data.get('expires_minutes') or 0)
        if not 3<=len(code)<=64: return jsonify(error='Channel ID must be 3–64 characters'),400
        expires=None if minutes<=0 else datetime.now(timezone.utc).timestamp()+min(minutes,10080)*60
        if expires: from datetime import datetime as D; expires=D.fromtimestamp(expires,timezone.utc)
        try:
            row=db.one('insert into channels(channel_code,name,password_hash,creator_session_hash,expires_at) values(%s,%s,%s,%s,%s) returning channel_code,name,expires_at',(code,name,bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode() if password else None,__import__('hashlib').sha256(session['sid'].encode()).hexdigest(),expires))
        except Exception: return jsonify(error='Channel ID already exists'),409
        return jsonify(channel=row)
    @app.post('/api/admin/login')
    def api_admin_login():
        data=request.get_json(silent=True) or {}
        if not verify_admin(str(data.get('username','')),str(data.get('password',''))):
            app.config['SECURITY_LOG']('admin_login_failed',{}); return jsonify(error='Invalid credentials'),401
        session['admin']=True; return jsonify(ok=True,csrf=session['csrf'])
    @app.post('/api/admin/logout')
    @admin_required
    def api_admin_logout(): session.pop('admin',None); return jsonify(ok=True)
    @app.get('/api/admin/overview')
    @admin_required
    def api_admin_overview():
        channels=db.active_channels(); violations=db.all_rows("select * from security_events where event_type='rate_limit' order by created_at desc limit 100"); return jsonify(channels=channels,violations=violations,sessions='anonymous/session cookies')
    @app.delete('/api/admin/channels/<code>')
    @admin_required
    def api_admin_delete_channel(code):
        db.execute('delete from channels where channel_code=%s',(clean_text(code,64),)); return jsonify(ok=True)
    @app.get('/api/admin/messages/<code>')
    @admin_required
    def api_admin_messages(code):
        rows=db.all_rows('select m.*,c.channel_code from messages m join channels c on c.id=m.channel_id where c.channel_code=%s order by m.created_at desc limit 500',(clean_text(code,64),))
        from .security import decrypt_message
        return jsonify(messages=[{'display_name':r['display_name'],'text':decrypt_message(r['nonce'],r['ciphertext']),'created_at':r['created_at'].isoformat()} for r in rows])
    register_socketio(socketio)
    if not app.debug and not os.environ.get('WERKZEUG_RUN_MAIN'): threading.Thread(target=cleanup_expired,daemon=True).start()
    app.socketio=socketio; return app
app=build_app()
if __name__=='__main__': app.socketio.run(app,host='0.0.0.0',port=int(os.environ.get('PORT','5000')))
