# Deploying SecureShop on a Domain

This guide walks through hosting SecureShop on a domain with HTTPS. SecureShop is
a standard WSGI (Flask) application, so it deploys like any other Python web app.

**Database note:** SecureShop uses **SQLite** (single file at
`instance/secureshop.db`), which needs no database server and is fine for a
single-instance store. If you run several app instances or expect high traffic,
switch to **PostgreSQL** (see §6).

---

## 1. Architecture in production

```
Client (https://yourdomain.com)
      │
      ▼
   nginx  (port 80/443, TLS termination)   ← reverse proxy
      │
      ▼
   gunicorn / waitress  (127.0.0.1:8000)   ← WSGI server
      │
      ▼
   SecureShop (Flask) ────▶ SQLite / PostgreSQL
```

The Flask dev server (`python run.py`) must **not** be used in production. Use a
WSGI server (gunicorn or waitress) behind a reverse proxy.

---

## 2. Option A — VPS with nginx + gunicorn (recommended)

Works on any Linux VPS (DigitalOcean, Hetzner, Linode, AWS EC2, etc.).

### 2.1 Server setup (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip nginx git

# create the app user and directory
sudo useradd -m -s /bin/bash secureshop
sudo mkdir -p /var/www/secureshop && sudo chown secureshop:secureshop /var/www/secureshop

# copy your code (or clone your repo)
cd /var/www/secureshop
git clone https://github.com/<you>/SecureShop.git .   # or upload your files

# virtual environment + dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-prod.txt
```

### 2.2 systemd service

Create `/etc/systemd/system/secureshop.service`:

```ini
[Unit]
Description=SecureShop
After=network.target

[Service]
User=secureshop
Group=secureshop
WorkingDirectory=/var/www/secureshop
Environment="SECURESHOP_HTTPS=1"
Environment="SECURESHOP_SECRET_KEY=<long-random-string>"
Environment="SECURESHOP_PEPPER=<another-random-string>"
Environment="SECURESHOP_MAIL_DEV=0"
ExecStart=/var/www/secureshop/.venv/bin/gunicorn -w 3 -b 127.0.0.1:8000 wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Start and enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secureshop
sudo systemctl status secureshop
```

Generate strong secrets with: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`

### 2.3 nginx reverse proxy + TLS

Point your domain's DNS `A` record at the server's IP first (see §4).

Create `/etc/nginx/sites-available/secureshop`:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable it and get a free TLS certificate:

```bash
sudo ln -s /etc/nginx/sites-available/secureshop /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# install certbot and issue the certificate (auto-configures HTTPS + redirect)
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Done — the store is live at `https://yourdomain.com`.

---

## 3. Option B — PaaS (fastest, no server admin)

These platforms deploy directly from a git repo and give you a free HTTPS domain
(you can add your own custom domain in their dashboard).

| Platform | Steps |
|---|---|
| **Render** | New Web Service → point at your repo → Build: `pip install -r requirements.txt -r requirements-prod.txt` → Start: `gunicorn -w 3 -b 0.0.0.0:$PORT wsgi:app` → add env vars (`SECURESHOP_SECRET_KEY`, `SECURESHOP_HTTPS=1`). |
| **Railway** | New Project → Deploy from repo → set start command `gunicorn -w 3 -b 0.0.0.0:$PORT wsgi:app` and env vars. |
| **Fly.io** | `fly launch` → uses a `Procfile`: `web: gunicorn -w 3 -b 0.0.0.0:8080 wsgi:app`. |
| **PythonAnywhere** | Web app → "Manual config (WSGI)" → set the WSGI file to import `wsgi:app` → uses the built-in proxy; add your domain under the Web tab. |

For these, the platform terminates TLS, so keep `SECURESHOP_HTTPS=1` set.

---

## 4. Pointing a domain

1. Buy a domain from any registrar (Namecheap, GoDaddy, Cloudflare, Google…).
2. Create a DNS record pointing the domain at your server:
   - `A` record: `@` → your server IP (and `www` → same IP), **or**
   - `CNAME`: `www` → your PaaS app hostname.
3. Wait a few minutes for DNS to propagate, then issue TLS (Let's Encrypt) or let
   the PaaS provision it.

If you use Cloudflare (recommended), enable **Full (strict)** SSL mode so the
connection is encrypted end-to-end.

---

## 5. Production checklist

- [ ] Set strong `SECURESHOP_SECRET_KEY` and `SECURESHOP_PEPPER` (never the auto-generated dev ones).
- [ ] Set `SECURESHOP_HTTPS=1` (enables `Secure` cookies + HSTS).
- [ ] Set `SECURESHOP_MAIL_DEV=0` and wire a real mailer for account confirmation/reset (or leave confirmations out until mail is configured).
- [ ] Change/remove the seeded accounts (`admin` / `alice` / `bob`) and set a strong admin password.
- [ ] Back up `instance/secureshop.db` regularly (it is the entire store state).
- [ ] Keep `debug=False` (already the default in `run.py` / `wsgi.py`).

---

## 6. Scaling the database (PostgreSQL)

SQLite is a single-file database and is ideal for one app instance. To scale
across multiple workers/servers, move to PostgreSQL:

1. Provision a PostgreSQL database (your VPS, or a managed service such as
   Neon, Supabase, or RDS).
2. Replace the SQLite connection layer in `secure_shop/db.py` with `psycopg2`
   (or SQLAlchemy), keeping the parameterised queries.
3. Adjust `DATABASE` in `secure_shop/config.py` to the PostgreSQL connection
   string (e.g. `postgresql://user:pass@host:5432/secureshop`).

The application's queries are written with parameter placeholders, so the change
is contained to `db.py` and `config.py`.

---

## 7. Windows hosting (waitress + IIS/nginx)

On a Windows server, run SecureShop with **waitress** (included in
`requirements-prod.txt`):

```powershell
pip install -r requirements.txt -r requirements-prod.txt
$env:SECURESHOP_HTTPS = "1"
waitress-serve --listen=0.0.0.0:8000 wsgi:app
```

Then put a reverse proxy (IIS ARR, or nginx for Windows) in front of it for
port 80/443 and TLS.
