# Free Hosting with HTTPS

Two solid **free** options, both giving you **HTTPS automatically**:

| | Render | PythonAnywhere |
|---|---|---|
| URL | `https://<name>.onrender.com` | `https://<user>.pythonanywhere.com` |
| Custom domain | ✅ free (auto TLS) | ❌ paid only |
| HTTPS | ✅ automatic | ✅ automatic |
| Database | SQLite (ephemeral on free) | SQLite (persistent) |
| Cost | Free tier | Free tier |

> **Which should I pick?**
> - Want a **custom domain** → use **Render**.
> - Want **persistent data with zero changes** (SQLite file survives restarts) → use **PythonAnywhere**.
> - Need both (custom domain + persistent data on free) → Render **plus** a free
>   PostgreSQL database (Neon free tier) — requires the small PostgreSQL switch
>   in `docs/DEPLOYMENT.md` §6.

---

## Option A — Render (free, custom domain, auto HTTPS)

Render has a ready-made config in this repo: [`render.yaml`](../render.yaml).

1. Push the repository to **GitHub**.
2. Go to <https://render.com> → sign up (GitHub account).
3. **New** → **Blueprint** → select your repo.
4. Render reads `render.yaml` and creates the service. It installs dependencies
   and starts `gunicorn ... wsgi:app`.
5. Your site is live at `https://secureshop.onrender.com` (HTTPS on by default).

**Add your own domain (free):**
1. In Render, open the service → **Settings** → **Custom Domains** → **Add**.
2. Enter `yourdomain.com`; Render gives you a DNS target.
3. At your registrar, add a `CNAME` (or `ALIAS`/`ANAME`) record for `www` and/or
   the apex to that target.
4. Render provisions a free TLS certificate automatically — wait a few minutes.

**Render free-tier notes:**
- The free instance **sleeps after ~15 minutes of no traffic**; the first request
  after sleep can take ~30–60 s to wake (fix it for free — see **Option A.2** below).
- Free services have **no persistent disk**, so the SQLite file resets on each
  redeploy. For persistent data, attach a free **Neon PostgreSQL** DB (below) or
  use PythonAnywhere.

### Option A.1 — Add a free Neon PostgreSQL database (persistent data)

SecureShop supports PostgreSQL automatically — just set the `DATABASE_URL`
environment variable to a `postgresql://…` URL.

1. Sign up at <https://neon.tech> (free tier: ~0.5 GB storage, enough for a store).
2. Create a **Project** → Neon gives you a connection string like:
   `postgresql://user:pass@ep-xxx.region.aws.neon.tech/neondb?sslmode=require`
3. In Render, open your service → **Environment** → add a variable:
   - Key: `DATABASE_URL`
   - Value: your Neon connection string
4. Render redeploys; on first boot SecureShop creates the tables and seeds the
   store into Neon. Data now persists across redeploys and restarts.

> Note: add `?sslmode=require` to the Neon URL (Neon requires TLS), or use the
> "connection string" Neon shows in its dashboard (it already includes it).

### Option A.2 — Keep it awake (stop the 15-minute sleep, free)

Render's free tier puts the app to sleep after ~15 minutes with no traffic.
A free uptime monitor that pings the site every 5 minutes prevents that sleep
(any HTTP request counts as traffic).

**With UptimeRobot (free):**

1. Sign up at <https://uptimerobot.com> (free account).
2. **+ New monitor** → type **HTTP(s)**.
3. Set:
   - Friendly name: `SecureShop`
   - URL: `https://yourdomain.com` (or your `https://….onrender.com` URL)
   - Monitoring interval: **5 minutes**
4. **Create monitor**. UptimeRobot now requests the homepage every 5 minutes, so
   Render never goes to sleep — your store loads instantly for real visitors.

**Alternative: cron-job.org (free)**

1. Sign up at <https://cron-job.org>.
2. **New cron job** → Address: `https://yourdomain.com/` → Schedule: **every 5 minutes**.
3. Save. Same effect: keeps the app warm.

> Tip: point the monitor at the **homepage** (`/`). Avoid `/admin` or login pages
> so the pings don't generate failed-login or rate-limit noise in your audit log.

---

## Option B — PythonAnywhere (free, persistent SQLite, auto HTTPS)

1. Sign up at <https://www.pythonanywhere.com> (free "Beginner" account).
2. Open a **Bash console** and upload the project to `/home/<youruser>/secureshop`
   (use the Files tab, `git clone`, or `zip` upload).
3. Create a virtualenv and install dependencies in the Bash console:
   ```bash
   mkvirtualenv --python=python3.10 secureshop
   pip install -r ~/secureshop/requirements.txt
   ```
4. **Web** tab → **Add a new web app** → **Manual configuration** → select the
   Python version that matches your virtualenv (e.g. 3.10).
5. Edit the **WSGI file** (linked from the Web tab) to:
   ```python
   import os
   # Production flags: cookies secure + behind the PythonAnywhere proxy.
   os.environ["SECURESHOP_HTTPS"] = "1"
   os.environ["SECURESHOP_TRUST_PROXY"] = "1"
   # Strong secrets — replace these with your own random values.
   os.environ["SECURESHOP_SECRET_KEY"] = "paste-a-long-random-string-here"
   os.environ["SECURESHOP_PEPPER"] = "paste-another-long-random-string-here"

   import sys
   path = "/home/<youruser>/secureshop"
   if path not in sys.path:
       sys.path.insert(0, path)

   from wsgi import app as application
   ```
6. Back on the Web tab, set the **virtualenv** path to the one you created
   (`/home/<youruser>/.virtualenvs/secureshop`).
7. Click **Reload**. Your store is live at
   `https://<youruser>.pythonanywhere.com` (HTTPS included).

**PythonAnywhere free-tier notes:**
- SQLite lives on your persistent home directory, so orders/products **survive
  restarts** — ideal for the current SQLite app.
- Custom domains and outbound SMTP (real email) are **paid** features. Without
  SMTP, keep `SECURESHOP_MAIL_DEV` default (confirmation links shown on-page).
- The free account must stay active (log in periodically) or the app may be
  paused.

---

## After going live (both platforms)

1. Log in as `admin` and **change the seeded admin password** (or create a new
   admin and deactivate `admin`).
2. Confirm the padlock (HTTPS) and that cookies are `Secure`.
3. Remove or restock the demo products, and add your real catalogue.
4. Set up regular backups of the database (SQLite file or PostgreSQL dump).
