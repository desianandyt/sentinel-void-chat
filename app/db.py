from __future__ import annotations
import os
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json

class SupabaseError(RuntimeError):
    def __init__(self,status,detail): self.status=status; self.detail=str(detail); super().__init__(self.detail)

def config():
    url=os.environ.get('SUPABASE_URL','').rstrip('/')
    key=os.environ.get('SUPABASE_SERVICE_ROLE_KEY','')
    if not url or not key: raise SupabaseError(503,'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required')
    return url+'/rest/v1',key

def request(method,table,params=None,body=None,prefer='return=representation'):
    base,key=config(); query=('?'+urlencode(params,doseq=True)) if params else ''
    data=None if body is None else json.dumps(body,default=str).encode()
    headers={'apikey':key,'Authorization':'Bearer '+key,'Content-Type':'application/json','Accept':'application/json','Prefer':prefer}
    try:
        with urlopen(Request(f'{base}/{table}{query}',data=data,headers=headers,method=method),timeout=15) as r:
            raw=r.read(); return json.loads(raw) if raw else []
    except HTTPError as e:
        detail=e.read().decode(errors='replace')[:600]
        raise SupabaseError(e.code,detail)
    except (URLError,TimeoutError,OSError) as e: raise SupabaseError(503,str(e))

def ensure_schema(): return None

def one(table,params=None,body=None,method='GET'):
    rows=request(method,table,params,body)
    return rows[0] if rows else None

def all_rows(table,params=None): return request('GET',table,params)
def _decode_bytea(value):
    if isinstance(value,bytes): return value
    text=str(value)
    return bytes.fromhex(text[2:] if text.startswith('\\x') else text)
def create_channel(code,name,password_hash,creator_hash,expires):
    return one('channels',body={'channel_code':code,'name':name,'password_hash':password_hash,'creator_session_hash':creator_hash,'expires_at':expires.isoformat() if expires else None},method='POST')
def find_channel(code):
    rows=all_rows('channels',{'channel_code':f'eq.{code}','deleted_at':'is.null','select':'*','limit':'1'})
    if not rows:return None
    row=rows[0]
    if row.get('expires_at') and datetime.fromisoformat(row['expires_at'].replace('Z','+00:00'))<=datetime.now(timezone.utc): return None
    return row
def channel_messages(channel_id,limit=100):
    rows=all_rows('messages',{'channel_id':f'eq.{channel_id}','select':'id,display_name,ciphertext,nonce,created_at','order':'created_at.desc','limit':str(limit)})
    for row in rows: row['ciphertext']=_decode_bytea(row['ciphertext']); row['nonce']=_decode_bytea(row['nonce'])
    return rows
def insert_message(channel_id,session_hash,display_name,ciphertext,nonce):
    return one('messages',body={'channel_id':channel_id,'session_hash':session_hash,'display_name':display_name,'ciphertext':'\\x'+ciphertext.hex(),'nonce':'\\x'+nonce.hex()},method='POST')
def active_channels(): return all_rows('channels',{'deleted_at':'is.null','select':'id,channel_code,name,expires_at,created_at','order':'created_at.desc'})
def security_events(limit=100): return all_rows('security_events',{'select':'id,event_type,ip,session_hash,detail,created_at','order':'created_at.desc','limit':str(limit)})
def blocked_ips(): return all_rows('blocked_ips',{'select':'ip,reason,created_at','order':'created_at.desc'})
def delete_channel(code): return request('DELETE','channels',{'channel_code':f'eq.{code}'},prefer='return=minimal')
def admin_messages(code):
    channels=all_rows('channels',{'channel_code':f'eq.{code}','select':'id','limit':'1'})
    if not channels:return []
    rows=all_rows('messages',{'channel_id':f'eq.{channels[0]["id"]}','select':'display_name,ciphertext,nonce,created_at','order':'created_at.desc','limit':'500'})
    for row in rows: row['ciphertext']=_decode_bytea(row['ciphertext']); row['nonce']=_decode_bytea(row['nonce'])
    return rows
def block_ip(ip,reason): return request('POST','blocked_ips',body={'ip':ip,'reason':reason},prefer='resolution=merge-duplicates,return=minimal')
def unblock_ip(ip): return request('DELETE','blocked_ips',{'ip':f'eq.{ip}'},prefer='return=minimal')
def log_security(event,detail,ip=None,shash=None):
    try: request('POST','security_events',body={'event_type':event,'ip':ip,'session_hash':shash,'detail':detail},prefer='return=minimal')
    except Exception: pass
def expired_channels(): return all_rows('channels',{'expires_at':'not.is.null','expires_at':'lt.'+datetime.now(timezone.utc).isoformat(),'select':'channel_code'})
def cleanup_expired():
    for row in expired_channels(): delete_channel(row['channel_code'])
