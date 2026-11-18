"""Lab 5 — Passkeys (FIDO2 / WebAuthn) — concept implementation.

A passkey is an asymmetric (FIDO2) credential: the server stores only the public
key; the private key never leaves the authenticator. At login the server sends a
fresh random challenge and the authenticator signs it after local user
verification. The server verifies the signature *and* that the credential id
matches — both are required, exactly as the lab's
``passkey_allowed(valid_signature, matching_credential)``.

This module implements the cryptography with Ed25519 so the concept can be
demonstrated and unit-tested. A production web app would drive the same flow
through the browser's WebAuthn API; the application's practical login path is
session auth + TOTP, with passkeys documented as the AAL3 upgrade.
"""
import hmac
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def register():
    """Create a new passkey. Returns a dict with the private key (kept only by
    the authenticator), the public key (sent to the server), and a credential id."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    credential_id = secrets.token_bytes(16)
    return {
        "private_key": private_key,
        "public_key": public_key,
        "credential_id": credential_id,
    }


def make_challenge(length=32):
    """A fresh, single-use random challenge for one login attempt."""
    return secrets.token_bytes(length)


def sign(private_key, challenge):
    """The authenticator signs the challenge (after local PIN/biometric)."""
    return private_key.sign(challenge)


def passkey_allowed(public_key, expected_credential_id, presented_credential_id,
                    signature, challenge):
    """Verify both (1) a valid signature over the challenge and (2) a matching
    credential id. Both must be true, like the lab's passkey_allowed(True, True)."""
    try:
        public_key.verify(signature, challenge)
        signature_ok = True
    except Exception:
        signature_ok = False
    id_ok = hmac.compare_digest(presented_credential_id, expected_credential_id)
    return signature_ok and id_ok
