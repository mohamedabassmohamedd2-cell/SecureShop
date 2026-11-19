"""Vercel serverless entry point (WSGI).

Vercel's Python runtime serves a top-level ``app`` that is a WSGI application.
All routes are rewired to this function in ``vercel.json``.

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

_FUNCTION_PREFIX = "/api/index"

_flask_app = create_app()


class VercelPathFix:
    """Normalise the request path for Vercel's serverless WSGI runtime.

    Vercel rewrites every request to the serverless function at ``/api/index``;
    depending on the runtime version the original path arrives either as an
    ``/api/index`` prefix in PATH_INFO, or split across SCRIPT_NAME + PATH_INFO.
    Strip that prefix (and reset SCRIPT_NAME) so Flask sees the real route.
    """

    def __init__(self, app, prefix=_FUNCTION_PREFIX):
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        script = environ.get("SCRIPT_NAME", "") or ""
        path = environ.get("PATH_INFO", "") or "/"
        full = script + path
        if full.startswith(self.prefix):
            remainder = full[len(self.prefix):]
            full = remainder if remainder.startswith("/") else ("/" + remainder)
        environ["SCRIPT_NAME"] = ""
        environ["PATH_INFO"] = full or "/"
        return self.app(environ, start_response)


app = VercelPathFix(_flask_app)
