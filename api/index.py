"""Vercel serverless entry point (WSGI).

Vercel's Python runtime serves a top-level ``app`` that is a WSGI application.
``vercel.json`` rewrites every request to ``/api/index/<original-path>``, so this
module also registers every route under that ``/api/index`` prefix. This keeps
``url_for()`` generating the clean (unprefixed) URLs that map back through
Vercel's rewrite, while routing works regardless of how Vercel passes paths.

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

_PREFIX = "/api/index"

app = create_app()

# Duplicate every route under the Vercel function prefix. Original (clean) routes
# are inserted first, so url_for() keeps returning unprefixed URLs.
for rule in list(app.url_map.iter_rules()):
    path = rule.rule
    if path.startswith(_PREFIX):
        continue
    app.add_url_rule(
        _PREFIX + path,
        rule.endpoint,
        app.view_functions[rule.endpoint],
        methods=rule.methods,
    )

# The root rewrite sends "/" -> "/api/index" (no trailing slash).
app.add_url_rule(
    _PREFIX, "shop.index", app.view_functions["shop.index"], methods=["GET"]
)
