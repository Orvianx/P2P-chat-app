"""
crypto.py — Cryptographic primitives + Network helpers
=======================================================
  • RSA-2048 key-pair generation & PEM serialisation
  • RSA-OAEP encrypt / decrypt   (key transport only)
  • Fernet (AES-128-CBC + HMAC-SHA256) for text messages
  • Fernet encrypt / decrypt for raw bytes (file chunks)
  • LAN / WAN IP detection helpers

Dependencies: Python stdlib + `cryptography` package.
"""

import socket
import urllib.request

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet


# ── RSA key generation ────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generate an ephemeral RSA-2048 key pair (never written to disk).
    Returns (private_key, public_key).
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


# ── RSA serialisation ─────────────────────────────────────────────────────────

def serialize_public_key(pub) -> bytes:
    """PEM-encode a public key for wire transmission."""
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem: bytes):
    """Reconstruct an RSAPublicKey from PEM bytes."""
    return serialization.load_pem_public_key(pem)


# ── RSA encrypt / decrypt (used only for AES key exchange) ───────────────────

def rsa_encrypt(pub, plaintext: bytes) -> bytes:
    """Encrypt bytes under an RSA public key (OAEP + SHA-256)."""
    return pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


def rsa_decrypt(priv, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP ciphertext with our private key."""
    return priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )


# ── AES / Fernet helpers ──────────────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """Generate a fresh Fernet key (AES-128-CBC + HMAC-SHA256, random IV per msg)."""
    return Fernet.generate_key()


def aes_encrypt(key: bytes, text: str) -> bytes:
    """Encrypt a UTF-8 string; returns a Fernet token."""
    return Fernet(key).encrypt(text.encode())


def aes_decrypt(key: bytes, token: bytes) -> str:
    """Decrypt a Fernet token to a UTF-8 string. Raises on tampering."""
    return Fernet(key).decrypt(token).decode()


def aes_encrypt_bytes(key: bytes, data: bytes) -> bytes:
    """Encrypt raw bytes (file chunk); returns a Fernet token."""
    return Fernet(key).encrypt(data)


def aes_decrypt_bytes(key: bytes, token: bytes) -> bytes:
    """Decrypt a Fernet token back to raw bytes."""
    return Fernet(key).decrypt(token)


# ── Network helpers ───────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the primary LAN IP (no packet sent; OS picks the interface)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def get_public_ip(timeout: int = 5) -> str:
    """
    Fetch the WAN IP from a plain-text HTTP provider.
    Falls back through three providers; returns 'unavailable' on failure.
    """
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "p2p-secure-chat/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ip = r.read().decode().strip()
                if len(ip.split(".")) == 4 and all(p.isdigit() for p in ip.split(".")):
                    return ip
        except Exception:
            continue
    return "unavailable"
