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

app = create_app()


class VercelPathFix:
    """WSGI middleware that normalises the path for Vercel's serverless runtime.

    Vercel rewrites every request to the function at ``/api/index``; the original
    path can arrive either as an ``/api/index`` prefix in PATH_INFO or split
    across SCRIPT_NAME + PATH_INFO. Strip that prefix so Flask sees the real
    route. Registered via the standard ``app.wsgi_app = middleware(...)`` pattern
    so ``app`` stays a genuine Flask instance.
    """

    def __init__(self, wsgi_app, prefix=_FUNCTION_PREFIX):
        self.wsgi_app = wsgi_app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        script = environ.get("SCRIPT_NAME", "") or ""
        path = environ.get("PATH_INFO", "") or "/"
        full = script + path
        if full == self.prefix:
            full = "/"
        elif full.startswith(self.prefix + "/"):
            full = full[len(self.prefix):]
        elif full.startswith(self.prefix):
            full = "/" + full[len(self.prefix):]

        def sr(status, headers, exc_info=None):
            headers.append(("X-Diag", f"script={script} path={path} -> {full}"))
            return start_response(status, headers, exc_info)

        environ["SCRIPT_NAME"] = ""
        environ["PATH_INFO"] = full or "/"
        return self.wsgi_app(environ, sr)


app.wsgi_app = VercelPathFix(app.wsgi_app)
