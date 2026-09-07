from __future__ import annotations
import base64, hashlib, os, secrets, time
from collections import defaultdict, deque
from functools import wraps
from typing import Callable
import bcrypt, bleach
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import abort, current_app, request, session

class Limiter:
    def __init__(self): self.buckets=defaultdict(deque)
    def allow(self,key,limit,window):
        now=time.monotonic(); q=self.buckets[key]
        while q and now-q[0]>=window: q.popleft()
        if len(q)>=limit: return False
        q.append(now); return True

limiter=Limiter()
def clean_text(value,max_len):
    value=bleach.clean(str(value or ''),tags=[],attributes={},strip=True)
    return ' '.join(value.split())[:max_len]
def client_ip(): return request.headers.get('CF-Connecting-IP',request.remote_addr or '0.0.0.0').split(',')[0].strip()
def session_hash(): return hashlib.sha256(session['sid'].encode()).hexdigest()
def ensure_identity():
    if not session.get('sid') or session.get('expires',0)<time.time(): abort(401)
    if client_ip() in current_app.config['BLOCKED_IPS']: abort(403)
def ensure_socket(data=None):
    if not session.get('sid') or session.get('expires',0)<time.time(): return False
    if client_ip() in current_app.config['BLOCKED_IPS']: return False
    token=(data or {}).get('csrf') if isinstance(data,dict) else None
    return bool(token and secrets.compare_digest(token,session.get('csrf','')))
def require_identity(fn:Callable):
    @wraps(fn)
    def wrapped(*a,**kw):
        ensure_identity()
        return fn(*a,**kw)
    return wrapped
def require_csrf():
    if request.method in {'POST','PUT','PATCH','DELETE'}:
        supplied=request.headers.get('X-CSRF-Token') or (request.get_json(silent=True) or {}).get('csrf')
        if not supplied or not secrets.compare_digest(supplied,session.get('csrf','')): abort(403,description='CSRF validation failed')
def rate_limit(name,limit,window,key=None):
    k=f'{name}:{key or client_ip()}:{session.get("sid","")}'
    if not limiter.allow(k,limit,window):
        current_app.config['SECURITY_LOG']('rate_limit',{'name':name})
        abort(429,description='Rate limit exceeded')
def new_identity():
    session.clear(); session['sid']=secrets.token_urlsafe(32); session['csrf']=secrets.token_urlsafe(32); session['expires']=time.time()+current_app.config['SESSION_TTL']
def encrypt_message(plaintext):
    nonce=os.urandom(12); data=AESGCM(current_app.config['MESSAGE_KEY']).encrypt(nonce,plaintext.encode(),None); return nonce,data
def decrypt_message(nonce,ciphertext): return AESGCM(current_app.config['MESSAGE_KEY']).decrypt(nonce,ciphertext,None).decode()
def verify_admin(username,password):
    return secrets.compare_digest(username,current_app.config['ADMIN_USERNAME']) and bcrypt.checkpw(password.encode(),current_app.config['ADMIN_PASSWORD_HASH'].encode())
def admin_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get('admin'): abort(401)
        require_csrf(); rate_limit('admin',60,60)
        return fn(*a,**kw)
    return wrapped
