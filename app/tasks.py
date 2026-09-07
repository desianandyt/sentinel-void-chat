import time
from .db import execute
from .db import all_rows

def cleanup_expired(app):
    while True:
        try:
            with app.app_context():
                execute("delete from channels where expires_at is not null and expires_at<=now()")
                rows=all_rows('select ip::text as ip from blocked_ips')
                app.config['BLOCKED_IPS'].update(r['ip'] for r in rows)
        except Exception:
            pass
        time.sleep(15)
