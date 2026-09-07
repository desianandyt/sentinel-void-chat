from flask import request, session
from flask_socketio import emit, join_room, leave_room
from . import db
from .security import clean_text, decrypt_message, encrypt_message, ensure_socket, limiter, session_hash

def timestamp(value):
    return value.isoformat() if hasattr(value,'isoformat') else str(value)

def register_socketio(socketio):
    @socketio.on('connect')
    def connected(auth=None):
        if not session.get('sid') or session.get('expires',0)<__import__('time').time():
            return False
        emit('ready',{'csrf':session['csrf']})
    @socketio.on('join_channel')
    def join(data):
        if not ensure_socket(data): emit('error',{'message':'Security validation failed'}); return
        if not limiter.allow(f"ws_join:{request.remote_addr}:{session.get('sid')}",20,60): emit('error',{'message':'Too many join attempts'}); return
        code=clean_text((data or {}).get('channel'),64); password=str((data or {}).get('password',''))
        try: ch=db.find_channel(code)
        except Exception: emit('error',{'message':'Channel service temporarily unavailable'}); return
        if not ch: emit('error',{'message':'Channel not found or expired'}); return
        if ch['password_hash']:
            import bcrypt
            if not bcrypt.checkpw(password.encode(),ch['password_hash'].encode()): emit('error',{'message':'Invalid channel password'}); return
        join_room(str(ch['id'])); session['channel_id']=str(ch['id']); session['channel_code']=code
        try:
            history=db.channel_messages(ch['id'],100)
            messages=[{'id':str(x['id']),'display_name':x['display_name'],'text':decrypt_message(x['nonce'],x['ciphertext']),'created_at':timestamp(x['created_at'])} for x in reversed(history)]
        except Exception: emit('error',{'message':'Unable to load channel history'}); return
        emit('joined',{'channel':code,'name':ch['name'],'expires_at':timestamp(ch['expires_at']) if ch['expires_at'] else None,'messages':messages})
    @socketio.on('send_message')
    def message(data):
        if not ensure_socket(data) or not session.get('channel_id'): emit('error',{'message':'Security validation failed'}); return
        key=f"ws:{request.remote_addr}:{session.get('sid')}"
        if not limiter.allow(key,5,10): emit('error',{'message':'Slow down — message limit reached'}); return
        text=clean_text((data or {}).get('text'),1000); name=clean_text(session.get('display_name','Guest'),40)
        if not text: return
        nonce,cipher=encrypt_message(text)
        try: row=db.insert_message(session['channel_id'],session_hash(),name,cipher,nonce)
        except Exception: emit('error',{'message':'Message could not be stored'}); return
        emit('message',{'id':str(row['id']),'display_name':name,'text':text,'created_at':timestamp(row['created_at'])},to=session['channel_id'])
    @socketio.on('leave_channel')
    def leave(data):
        if not ensure_socket(data): return
        if session.get('channel_id'): leave_room(session['channel_id']); session.pop('channel_id',None)
