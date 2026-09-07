from __future__ import annotations
import base64, os, re, threading, time
from datetime import datetime, timezone
import bcrypt
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException
from flask_socketio import SocketIO
from . import db
from .realtime import register_socketio
from .security import admin_required, clean_text, client_ip, ensure_identity, new_identity, rate_limit, require_csrf, verify_admin
from .tasks import cleanup_expired
load_dotenv()

def build_app():
    app=Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY','dev-only-change-me'),SESSION_TTL=int(os.environ.get('SESSION_TTL_SECONDS','86400')),COOKIE_SECURE=os.environ.get('COOKIE_SECURE','false').lower()=='true',ADMIN_USERNAME=os.environ.get('ADMIN_USERNAME','anand'),ADMIN_PASSWORD_HASH=os.environ.get('ADMIN_PASSWORD_HASH','$2a$12$41RM.C2hJqdLbbMZNXvC0ezrmM4Vhm0PiFiVASDj/eVN/qRtF450i'),BLOCKED_IPS=set(),SECURITY_LOG=lambda e,d: None)
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
    try:
        db.ensure_schema()
    except Exception as exc:
        app.logger.warning('Database schema bootstrap unavailable: %s',exc)
    @app.errorhandler(HTTPException)
    def api_http_error(error):
        if request.path.startswith('/api/'):
            return jsonify(error=error.description or error.name), error.code
        return error
    @app.errorhandler(Exception)
    def api_unhandled_error(error):
        app.logger.exception('Unhandled application error')
        if request.path.startswith('/api/'):
            return jsonify(error='Server error. Please try again.'), 500
        raise error
    socketio=SocketIO(app,async_mode='eventlet',cors_allowed_origins=os.environ.get('CORS_ORIGINS','http://localhost:5000').split(','),logger=False,message_queue=os.environ.get('REDIS_URL'))
    @app.before_request
    def guard():
        if request.endpoint == 'api_admin_login':
            if not session.get('sid'): new_identity()
            rate_limit('admin_login',10,60)
            return
        if request.endpoint and request.endpoint.startswith('api_'):
            ensure_identity(); require_csrf(); rate_limit('http',120,60)
    @app.get('/')
    def index():
        if not session.get('sid'): new_identity()
        return render_template('index.html',csrf=session['csrf'])
    @app.get('/admin')
    def admin():
        if not session.get('sid'): new_identity()
        return render_template('admin.html',csrf=session['csrf'])
    @app.get('/healthz')
    def health():
        try:
            db.one('select 1 from channels limit 0')
            return {'status':'ok','database':'ok','driver':'pg8000'}
        except Exception as exc:
            message=str(exc).lower()
            if 'timeout' in message or 'timed out' in message: category='timeout'
            elif 'authentication' in message or 'password' in message: category='authentication'
            elif 'ssl' in message or 'certificate' in message: category='ssl'
            elif 'resolve' in message or 'name or service' in message or 'host' in message: category='hostname'
            else: category='connection_or_schema'
            return jsonify(status='degraded',database='unavailable',driver='pg8000',database_error=category),503
    @app.post('/api/session')
    def api_session():
        data=request.get_json(silent=True) or {}; name=clean_text(data.get('display_name'),40)
        if len(name)<2: return jsonify(error='Display name must be 2–40 characters'),400
        session['display_name']=name
        return jsonify(csrf=session['csrf'],display_name=name)
    @app.post('/api/channels')
    def api_create_channel():
        import bcrypt
        data=request.get_json(silent=True) or {}; code=clean_text(data.get('channel_id'),64); name=clean_text(data.get('name') or code,80); password=str(data.get('password') or '')[:128]
        try: minutes=int(data.get('expires_minutes') or 0)
        except (TypeError,ValueError): return jsonify(error='Expiry must be a number of minutes'),400
        if not 3<=len(code)<=64 or not re.fullmatch(r'[A-Za-z0-9_-]+',code): return jsonify(error='Channel ID may contain only letters, numbers, hyphens, and underscores'),400
        expires=None if minutes<=0 else datetime.now(timezone.utc).timestamp()+min(minutes,10080)*60
        if expires: from datetime import datetime as D; expires=D.fromtimestamp(expires,timezone.utc)
        try:
            row=db.one('insert into channels(channel_code,name,password_hash,creator_session_hash,expires_at) values(%s,%s,%s,%s,%s) returning channel_code,name,expires_at',(code,name,bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode() if password else None,__import__('hashlib').sha256(session['sid'].encode()).hexdigest(),expires))
        except Exception as exc:
            if db.is_unique_violation(exc): return jsonify(error='Channel ID already exists'),409
            if db.is_database_error(exc): return jsonify(error='Database unavailable. Check DATABASE_URL and run schema.sql in Supabase.'),503
            raise
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
        channels=db.active_channels(); violations=db.all_rows("select id,event_type,ip::text as ip,session_hash,detail,created_at from security_events order by created_at desc limit 100"); blocked=db.all_rows('select ip::text as ip,reason,created_at from blocked_ips order by created_at desc')
        return jsonify(channels=channels,violations=violations,blocked_ips=blocked,sessions='anonymous/session cookies')
    @app.get('/api/admin/live')
    @admin_required
    def api_admin_live():
        security=db.all_rows("select event_type,ip::text as ip,detail,created_at from security_events order by created_at desc limit 40")
        messages=db.all_rows("select c.channel_code,m.display_name,m.ciphertext,m.nonce,m.created_at from messages m join channels c on c.id=m.channel_id order by m.created_at desc limit 40")
        from .security import decrypt_message
        events=[{'type':'security','label':r['event_type'],'channel':'—','actor':r['ip'] or 'unknown','detail':r['detail'],'created_at':r['created_at'].isoformat()} for r in security]
        for r in messages:
            try: text=decrypt_message(r['nonce'],r['ciphertext'])
            except Exception: text='[unable to decrypt]'
            events.append({'type':'message','label':'message','channel':r['channel_code'],'actor':r['display_name'],'detail':{'text':text},'created_at':r['created_at'].isoformat()})
        events.sort(key=lambda x:x['created_at'],reverse=True)
        return jsonify(events=events[:60],server_time=datetime.now(timezone.utc).isoformat())
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
    @app.post('/api/admin/blocked-ips')
    @admin_required
    def api_admin_block_ip():
        data=request.get_json(silent=True) or {}; ip=clean_text(data.get('ip'),64); reason=clean_text(data.get('reason') or 'Blocked by administrator',200)
        import ipaddress
        try: ipaddress.ip_address(ip)
        except ValueError: return jsonify(error='Invalid IP address'),400
        db.execute('insert into blocked_ips(ip,reason) values(%s,%s) on conflict(ip) do update set reason=excluded.reason',(ip,reason)); app.config['BLOCKED_IPS'].add(ip); return jsonify(ok=True)
    @app.delete('/api/admin/blocked-ips/<ip>')
    @admin_required
    def api_admin_unblock_ip(ip):
        db.execute('delete from blocked_ips where ip=%s',(clean_text(ip,64),)); app.config['BLOCKED_IPS'].discard(ip); return jsonify(ok=True)
    register_socketio(socketio)
    if not app.debug and not os.environ.get('WERKZEUG_RUN_MAIN'): threading.Thread(target=cleanup_expired,args=(app,),daemon=True).start()
    app.socketio=socketio; return app
app=build_app()
if __name__=='__main__': app.socketio.run(app,host='0.0.0.0',port=int(os.environ.get('PORT','5000')))
