import os
import base64
import hashlib
from dataclasses import dataclass

DEFAULT_ITERS = 200_000
SALT_LEN = 16

@dataclass
class KdfParams:
    salt: bytes
    iters: int
    alg: str = "PBKDF2-SHA256"

def make_salt(n: int = SALT_LEN) -> bytes:
    return os.urandom(n)

def kdf_pbkdf2_sha256(password: str, salt: bytes, length: int, iters: int = DEFAULT_ITERS) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iters,
        dklen=length,
    )

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def hexkey(b: bytes) -> str:
    return b.hex()
