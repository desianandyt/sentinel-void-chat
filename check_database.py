#!/usr/bin/env python3
"""Safe Supabase PostgreSQL preflight checker using pg8000.

Install:
  pip install pg8000
Run:
  python check_database.py

The DATABASE_URL is requested without echoing it. No password is stored or
printed. The write test uses a temporary table and is rolled back.
"""
from __future__ import annotations
import getpass
import os
import sys
from urllib.parse import unquote, urlparse

try:
    import pg8000.dbapi as pg
except ImportError:
    print('Missing dependency. Install it with: pip install pg8000')
    sys.exit(2)

REQUIRED = {
    'channels': {'id','channel_code','name','password_hash','creator_session_hash','expires_at','created_at','deleted_at'},
    'messages': {'id','channel_id','session_hash','display_name','ciphertext','nonce','created_at'},
    'security_events': {'id','event_type','ip','session_hash','detail','created_at'},
    'blocked_ips': {'ip','reason','created_at'},
    'admin_audit_logs': {'id','action','actor','ip','metadata','created_at'},
}

def fail(message):
    print(f'FAIL  {message}')
    raise SystemExit(1)

def main():
    url = os.environ.get('DATABASE_URL') or getpass.getpass('Paste Supabase DATABASE_URL (input hidden): ')
    if not url.startswith(('postgresql://','postgres://')):
        fail('URL must start with postgresql:// or postgres://')
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.path.strip('/'):
        fail('URL is missing a host or database name')
    user = unquote(parsed.username or '')
    password = unquote(parsed.password or '')
    database = unquote(parsed.path.lstrip('/'))
    port = parsed.port or 5432
    print(f'Checking host: {parsed.hostname}:{port}')
    conn = None
    try:
        conn = pg.connect(user=user, password=password, host=parsed.hostname, port=port, database=database, timeout=10, ssl_context=True)
        cur = conn.cursor()
        cur.execute('select current_database(), current_user, version()')
        db, db_user, version = cur.fetchone()
        print(f'PASS  connection: database={db}, user={db_user}')
        print(f'INFO  {version.splitlines()[0]}')
        cur.execute("select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE'")
        tables = {row[0] for row in cur.fetchall()}
        missing_tables = set(REQUIRED) - tables
        if missing_tables:
            fail('missing tables: ' + ', '.join(sorted(missing_tables)) + '. Run schema.sql in Supabase SQL Editor.')
        print('PASS  required tables exist')
        for table, expected in REQUIRED.items():
            cur.execute('select column_name from information_schema.columns where table_schema=%s and table_name=%s', ('public', table))
            columns = {row[0] for row in cur.fetchall()}
            missing = expected - columns
            if missing: fail(f'{table} is missing columns: {", ".join(sorted(missing))}')
        print('PASS  required columns exist')
        for table in ('channels','messages','security_events'):
            cur.execute(f'select 1 from public.{table} limit 0')
        print('PASS  application read permissions')
        cur.execute('create temporary table void_chat_preflight(value integer)')
        cur.execute('insert into void_chat_preflight values (1)')
        conn.rollback()
        print('PASS  temporary write permission (rolled back; no app data changed)')
    except Exception as exc:
        message = str(exc).splitlines()[0]
        if 'timeout' in message.lower() or 'connect' in message.lower() or 'resolve' in message.lower():
            fail('connection failed. Use Supabase Transaction Pooler URL on port 6543. Details: ' + message)
        fail('database check failed: ' + message)
    finally:
        if conn is not None:
            conn.close()
    print('\nDATABASE READY for Render')
    print('Use the same DATABASE_URL in Render Environment Variables.')

if __name__ == '__main__':
    main()
