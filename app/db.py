from __future__ import annotations
import json, os
from contextlib import contextmanager
import psycopg
from psycopg.rows import dict_row

def db_url(): return os.environ['DATABASE_URL']
@contextmanager
def conn():
    with psycopg.connect(db_url(),row_factory=dict_row) as c:
        yield c
        c.commit()
def one(sql,params=()):
    with conn() as c:
        return c.execute(sql,params).fetchone()
def all_rows(sql,params=()):
    with conn() as c: return c.execute(sql,params).fetchall()
def execute(sql,params=()):
    with conn() as c: c.execute(sql,params)
def log_security(event,detail,ip=None,shash=None):
    execute('insert into security_events(event_type,ip,session_hash,detail) values(%s,%s,%s,%s)',(event,ip,shash,json.dumps(detail)))
def active_channels():
    return all_rows("select id::text as id,channel_code,name,expires_at,created_at from channels where deleted_at is null and (expires_at is null or expires_at>now()) order by created_at desc")
