import time
from .db import execute

def cleanup_expired():
    while True:
        try:
            execute("delete from channels where expires_at is not null and expires_at<=now()")
        except Exception:
            pass
        time.sleep(15)
