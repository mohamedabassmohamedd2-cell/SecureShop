"""SecureShop entry point.

Run:  python run.py
Then open http://127.0.0.1:5000

Set SECURESHOP_SECRET_KEY / SECURESHOP_PEPPER in the environment to override the
auto-generated instance secret. Set SECURESHOP_HTTPS=1 when serving behind TLS
to enable Secure cookies and HSTS.
"""
import os

from secure_shop import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("SECURESHOP_HOST", "127.0.0.1")
    port = int(os.environ.get("SECURESHOP_PORT", "5000"))
    # debug=False in production; never run with the debugger exposed on a network.
    app.run(host=host, port=port, debug=False)
