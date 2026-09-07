#!/usr/bin/env python3
"""Safe preflight check for VOID//CHAT's Supabase PostgreSQL database.

Usage:
  pip install "psycopg[binary]"
  python check_database.py

The script prompts for the full DATABASE_URL without printing it, checks
connectivity, required tables/columns, read access, and temporary write access.
It never creates application data and never stores the password.
"""
from __future__ import annotations
import getpass
import os
import sys
from urllib.parse import urlparse

try:
    import psycopg
except ImportError:
    print('Missing dependency. Install it with: pip install "psycopg[binary]"')
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
    sys.exit(1)

def main():
    url = os.environ.get('DATABASE_URL') or getpass.getpass('Paste Supabase DATABASE_URL (input hidden): ')
    if not url.startswith(('postgresql://','postgres://')):
        fail('URL must start with postgresql:// or postgres://')
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.path:
        fail('URL is missing a host or database name')
    print(f'Checking host: {parsed.hostname}:{parsed.port or 5432}')
    try:
        with psycopg.connect(url, connect_timeout=10) as conn:
            with conn.cursor() as cur:
                cur.execute('select current_database(), current_user, version()')
                db, user, version = cur.fetchone()
                print(f'PASS  connection: database={db}, user={user}')
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
                cur.execute('select 1 from public.channels limit 0')
                cur.execute('select 1 from public.messages limit 0')
                cur.execute('select 1 from public.security_events limit 0')
                print('PASS  application read permissions')
                cur.execute('create temporary table void_chat_preflight(value integer)')
                cur.execute('insert into void_chat_preflight values (1)')
                conn.rollback()
                print('PASS  temporary write permission (rolled back; no app data changed)')
    except psycopg.OperationalError as exc:
        fail('connection failed. Use Supabase Transaction Pooler URL on port 6543. Details: ' + str(exc).splitlines()[0])
    except psycopg.Error as exc:
        fail('database check failed: ' + str(exc).splitlines()[0])
    print('\nDATABASE READY for Render')
    print('Use the same DATABASE_URL in Render Environment Variables.')

if __name__ == '__main__':
    main()
