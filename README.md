# VOID//CHAT

Anonymous real-time chat built with Flask, Flask-SocketIO, PostgreSQL/Supabase, Redis, and a supplied Sentinel Admin UI. The public interface is dark sci-fi; `/admin` preserves the provided light Sentinel dashboard styling and adds channel, violation, deletion, and decrypted-log operations.

## Security model

Anonymous users receive a signed, HttpOnly, SameSite session cookie. The server stores only a SHA-256 session identifier with message rows. Messages are encrypted before insertion with AES-256-GCM; the nonce is stored beside the ciphertext and the encryption key is server-only. User-controlled strings are stripped of HTML with Bleach, capped by length, and every database query is parameterized. POST/PUT/PATCH/DELETE API calls require the session CSRF token. Socket.IO connections require the same token during the handshake and every message event. HTTP and WebSocket rate limits are enforced separately. Admin authentication uses a username plus bcrypt password hash, and admin actions are protected by the same session/CSRF controls.

## Run locally

1. Create a Supabase project and run `schema.sql` in the SQL editor.
2. Copy `.env.example` to `.env`. Set `DATABASE_URL` to the Supabase server-side connection string, not an anon browser key. Generate a 32-byte encryption key with `python -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"` and place it in `MESSAGE_ENCRYPTION_KEY`.
3. For the requested local credentials, the defaults are username `anand` and password `papaanand`; replace `ADMIN_PASSWORD_HASH` in production with a newly generated bcrypt hash.
4. Run `docker compose up --build`, then open `http://localhost:5000`. Open `/admin` for the dashboard.

## Deployment

Render can use the included `render.yaml` and `Dockerfile`. Add `DATABASE_URL`, `REDIS_URL`, `MESSAGE_ENCRYPTION_KEY`, `SECRET_KEY`, and a production `ADMIN_PASSWORD_HASH` as secrets. Run one web instance for the built-in expiry worker, or move cleanup to a single worker/cron process when scaling horizontally. For multiple web instances, configure Redis message queue support and use a distributed rate limiter implementation in place of the in-memory fallback.

## Important operational notes

The ephemeral cleanup worker permanently deletes expired channels; PostgreSQL `ON DELETE CASCADE` wipes their messages. Backups, WAL retention, and database snapshots can still preserve historical data, so configure Supabase retention according to the privacy promise you make to users. Never expose the service-role database credential, encryption key, or admin password hash to the frontend.
