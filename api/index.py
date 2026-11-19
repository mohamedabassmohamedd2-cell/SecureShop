"""Vercel serverless entry point (WSGI).

Vercel's Python runtime serves a top-level ``app`` that is a WSGI application.
``vercel.json`` rewrites every request to ``/api/index/<original-path>``; the
route mirroring for that prefix lives inside ``create_app()``.

Requires these environment variables (set in the Vercel dashboard):

- ``DATABASE_URL``          -> a Neon ``postgresql://`` URL (Vercel has no disk)
- ``SECURESHOP_SECRET_KEY`` -> a long random string
- ``SECURESHOP_PEPPER``     -> a long random string
- ``SECURESHOP_HTTPS``      -> "1"
- ``SECURESHOP_TRUST_PROXY``-> "1"
"""
import os
import sys

# Make the repository root (which contains the `secure_shop` package) importable
# regardless of the serverless function's working directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_shop import create_app  # noqa: E402

app = create_app()
