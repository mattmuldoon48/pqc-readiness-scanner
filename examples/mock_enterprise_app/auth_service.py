from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

JWT_ALGORITHM = "RS256"
SERVICE_KEY = Path("/etc/identity/prod/auth_rsa_private_key.pem")
ECDSA_CURVE = ec.SECP256R1()

FAKE_LEGACY_TEST_KEY = """-----BEGIN RSA PRIVATE KEY-----
not-a-real-secret-demo-only
-----END RSA PRIVATE KEY-----"""


def issue_token(user_id: str) -> str:
    private_key = SERVICE_KEY.read_text()
    return jwt.encode({"sub": user_id}, private_key, algorithm=JWT_ALGORITHM)


def build_test_key():
    # Fake demo key generation used by legacy integration tests.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def verify_signature(public_key, message, signature):
    return public_key.verify(signature, message, padding.PKCS1v15(), None)
