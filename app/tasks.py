import time
from . import db

def cleanup_expired(app):
    while True:
        try:
            with app.app_context():
                db.cleanup_expired()
                rows=db.blocked_ips()
                app.config['BLOCKED_IPS'].update(r['ip'] for r in rows)
        except Exception:
            pass
        time.sleep(15)
