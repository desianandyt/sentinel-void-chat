from __future__ import annotations
import json, os
from contextlib import contextmanager
from urllib.parse import unquote, urlparse
import pg8000.dbapi as pg


def db_parts():
    parsed=urlparse(os.environ['DATABASE_URL'])
    return dict(user=unquote(parsed.username or ''),password=unquote(parsed.password or ''),host=parsed.hostname,port=parsed.port or 5432,database=unquote(parsed.path.lstrip('/')),timeout=10,ssl_context=True)

@contextmanager
def conn():
    c=pg.connect(**db_parts())
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()

def _rows(cur):
    columns=[x[0] for x in cur.description] if cur.description else []
    return [dict(zip(columns,row)) for row in cur.fetchall()]

def one(sql,params=()):
    with conn() as c:
        cur=c.cursor(); cur.execute(sql,params); rows=_rows(cur)
        return rows[0] if rows else None

def all_rows(sql,params=()):
    with conn() as c:
        cur=c.cursor(); cur.execute(sql,params); return _rows(cur)

def execute(sql,params=()):
    with conn() as c: c.cursor().execute(sql,params)

def ensure_schema():
    statements=[
        'create extension if not exists pgcrypto',
        '''create table if not exists channels (id uuid primary key default gen_random_uuid(), channel_code varchar(64) not null unique, name varchar(80) not null, password_hash text, creator_session_hash char(64) not null, expires_at timestamptz, created_at timestamptz not null default now(), deleted_at timestamptz)''',
        '''create table if not exists messages (id uuid primary key default gen_random_uuid(), channel_id uuid not null references channels(id) on delete cascade, session_hash char(64) not null, display_name varchar(40) not null, ciphertext bytea not null, nonce bytea not null, created_at timestamptz not null default now())''',
        '''create table if not exists admin_audit_logs (id bigserial primary key, action varchar(80) not null, actor varchar(80) not null, ip inet, metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now())''',
        '''create table if not exists security_events (id bigserial primary key, event_type varchar(80) not null, ip inet, session_hash char(64), detail jsonb not null default '{}'::jsonb, created_at timestamptz not null default now())''',
        '''create table if not exists blocked_ips (ip inet primary key, reason text, created_at timestamptz not null default now())''',
        'create index if not exists channels_expiry_idx on channels(expires_at)',
        'create index if not exists messages_channel_created_idx on messages(channel_id,created_at)'
    ]
    with conn() as c:
        cur=c.cursor()
        for statement in statements: cur.execute(statement)

def is_unique_violation(exc):
    return 'duplicate key' in str(exc).lower() or 'unique constraint' in str(exc).lower()
def is_database_error(exc):
    return isinstance(exc,(pg.Error,OSError))
def log_security(event,detail,ip=None,shash=None):
    execute('insert into security_events(event_type,ip,session_hash,detail) values(%s,%s,%s,%s)',(event,ip,shash,json.dumps(detail)))
def active_channels():
    return all_rows("select id::text as id,channel_code,name,expires_at,created_at from channels where deleted_at is null and (expires_at is null or expires_at>now()) order by created_at desc")
