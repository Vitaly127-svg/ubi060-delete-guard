import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo))


def sign_policy(policy: dict, private: bytes) -> str:
    key = serialization.load_pem_private_key(private, password=None)
    signature = key.sign(bytes.fromhex(digest(policy)),
                         padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                         utils.Prehashed(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def valid_policy(policy: dict, signature: str, public: bytes) -> bool:
    try:
        key = serialization.load_pem_public_key(public)
        key.verify(base64.b64decode(signature, validate=True), bytes.fromhex(digest(policy)),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                   utils.Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    result = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return "pbkdf2$600000$" + salt.hex() + "$" + result.hex()


def password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2" or int(rounds) != 600_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def issue_token(subject: str, role: str, private: bytes, lifetime: int = 900) -> str:
    now = int(time.time())
    return jwt.encode({"sub": subject, "role": role, "iat": now, "exp": now + lifetime,
                       "iss": "ubi060-auth", "aud": "ubi060", "jti": str(uuid.uuid4())},
                      private, algorithm="RS256")


def verify_token(token: str, public: bytes) -> dict:
    claims = jwt.decode(token, public, algorithms=["RS256"], audience="ubi060",
                        issuer="ubi060-auth", options={"require": ["sub", "role", "exp", "iat", "jti"]})
    if claims["role"] not in {"analyst", "owner", "admin", "scheduler"}:
        raise jwt.InvalidTokenError("Unknown role")
    return claims
