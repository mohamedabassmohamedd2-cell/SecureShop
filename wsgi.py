"""Production WSGI entry point.

Used by a production WSGI server, e.g.:

    gunicorn -w 3 -b 0.0.0.0:8000 wsgi:app      # Linux / macOS
    waitress-serve --listen=0.0.0.0:8000 wsgi:app   # Windows

The Flask development server (`python run.py`) is NOT for production.
"""
from secure_shop import create_app

app = create_app()
