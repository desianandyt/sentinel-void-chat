# Deploying VOID//CHAT on Render

## 1. Create the database

Create a Supabase project, open the SQL Editor, and run `schema.sql`. Copy the server-side PostgreSQL connection string from Supabase. Do not use the browser anon key as `DATABASE_URL`.

## 2. Create the Render service

Push this folder to GitHub, then choose **New → Blueprint** in Render and select the repository. Render detects `render.yaml` and creates the Docker web service. The service listens on Render's `PORT` automatically and exposes `/healthz` for health checks.

The included Blueprint uses the Starter plan because long-lived WebSocket connections and the in-process expiry worker should not run on a sleeping service. If the chosen Render plan supports WebSockets and an always-on process, the service can use that plan instead.

## 3. Add secrets

Set these values in the Render service environment:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Supabase server-side PostgreSQL URL |
| `REDIS_URL` | Render Redis URL, if using multi-instance deployment |
| `MESSAGE_ENCRYPTION_KEY` | URL-safe base64 encoding of exactly 32 random bytes |
| `ADMIN_PASSWORD_HASH` | bcrypt hash of the production admin password |
| `SECRET_KEY` | Render-generated secret, or a long random value |
| `ADMIN_USERNAME` | `anand`, or another administrator name |
| `COOKIE_SECURE` | `true` |
| `CORS_ORIGINS` | Your Render service URL, for example `https://anonymous-secure-chat.onrender.com` |

Generate a new encryption key locally with:

```bash
python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Generate a production bcrypt password hash with:

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'REPLACE_ME', bcrypt.gensalt()).decode())"
```

The development fallback credentials are `anand` / `papaanand`; replace the password hash before production use.

## 4. Verify

After deployment, open:

- `https://YOUR-SERVICE.onrender.com/` for anonymous chat
- `https://YOUR-SERVICE.onrender.com/admin` for the Sentinel Admin dashboard
- `https://YOUR-SERVICE.onrender.com/healthz` for the health check

## Scaling note

Run one Render web instance while using the built-in expiry worker. If scaling to multiple instances, use Render Redis for Socket.IO's message queue and replace the process-local rate limiter with a Redis-backed limiter so limits are shared across instances. Keep the encryption key unchanged across all instances; changing it makes existing ciphertext undecryptable.
